//! Allowlisted environment-backed Secrets Provider Module for Lenso vNext.

use std::{collections::BTreeMap, error::Error, fmt, rc::Rc};

use lenso_capability_secrets::{
    ResolveError, ResolveRequest, ResolveResponse, Secrets, SecretsEndpoint,
    SecretsInvocationError, SecretsProvider,
};
use lenso_kernel::{
    InvocationContext, ModuleFuture, ModuleLifecycle, NativeRequestEndpoint, NativeRequestFuture,
    PrepareContext, RuntimeFailure,
};
use lenso_native_adapter::{NativeModuleFactory, NativeModuleFactoryContext, NativeModuleInstance};

/// Maximum supported logical secret-reference length.
pub const MAX_REFERENCE_LENGTH: usize = 256;

/// Invalid immutable configuration supplied by the host author.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvSecretsConfigError {
    /// At least one required reference must be declared.
    Empty,
    /// A logical reference is not a canonical non-empty path.
    InvalidReference,
    /// An environment-variable name is not a portable process identifier.
    InvalidEnvironmentVariable,
    /// The same logical reference was configured more than once.
    DuplicateReference,
}

impl fmt::Display for EnvSecretsConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("at least one secret reference is required"),
            Self::InvalidReference => formatter.write_str("invalid logical secret reference"),
            Self::InvalidEnvironmentVariable => {
                formatter.write_str("invalid environment-variable name")
            }
            Self::DuplicateReference => {
                formatter.write_str("logical secret reference is already configured")
            }
        }
    }
}

impl Error for EnvSecretsConfigError {}

/// Immutable logical-reference allowlist for one Module Instance.
#[derive(Clone, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvSecretsConfig {
    #[serde(rename = "references", deserialize_with = "deserialize_unique_sources")]
    sources: BTreeMap<String, String>,
}

impl EnvSecretsConfig {
    /// Creates an empty allowlist.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sources: BTreeMap::new(),
        }
    }

    /// Adds one required logical reference and its environment source.
    pub fn insert(
        &mut self,
        reference: impl Into<String>,
        environment_variable: impl Into<String>,
    ) -> Result<(), EnvSecretsConfigError> {
        let reference = reference.into();
        let environment_variable = environment_variable.into();
        if !valid_reference(&reference) {
            return Err(EnvSecretsConfigError::InvalidReference);
        }
        if !valid_environment_variable(&environment_variable) {
            return Err(EnvSecretsConfigError::InvalidEnvironmentVariable);
        }
        if self.sources.contains_key(&reference) {
            return Err(EnvSecretsConfigError::DuplicateReference);
        }
        self.sources.insert(reference, environment_variable);
        Ok(())
    }

    /// Adds one required mapping through a consuming builder style.
    pub fn with_reference(
        mut self,
        reference: impl Into<String>,
        environment_variable: impl Into<String>,
    ) -> Result<Self, EnvSecretsConfigError> {
        self.insert(reference, environment_variable)?;
        Ok(self)
    }

    /// Returns whether no references are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Returns the number of explicitly configured references.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    fn source_for(&self, reference: &str) -> Option<&str> {
        self.sources.get(reference).map(String::as_str)
    }

    fn validate(&self) -> Result<(), EnvSecretsConfigError> {
        if self.sources.is_empty() {
            return Err(EnvSecretsConfigError::Empty);
        }
        for (reference, environment_variable) in &self.sources {
            if !valid_reference(reference) {
                return Err(EnvSecretsConfigError::InvalidReference);
            }
            if !valid_environment_variable(environment_variable) {
                return Err(EnvSecretsConfigError::InvalidEnvironmentVariable);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for EnvSecretsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvSecretsConfig")
            .field("references", &self.sources.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Native Rust factory for one allowlisted environment-backed Provider.
#[derive(Clone, Debug)]
pub struct EnvSecretsFactory {
    source: Rc<dyn SecretSource>,
}

impl EnvSecretsFactory {
    /// Creates a Provider that reads the current process environment.
    #[must_use]
    pub fn new() -> Self {
        Self {
            source: Rc::new(ProcessEnvironment),
        }
    }

    #[cfg(test)]
    fn with_source(source: Rc<dyn SecretSource>) -> Self {
        Self { source }
    }
}

impl Default for EnvSecretsFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeModuleFactory for EnvSecretsFactory {
    fn package_id(&self) -> &'static str {
        PACKAGE_ID
    }

    fn package_version(&self) -> &'static str {
        PACKAGE_VERSION
    }

    fn instantiate(
        &self,
        context: NativeModuleFactoryContext<'_>,
    ) -> Result<NativeModuleInstance, RuntimeFailure> {
        instantiate_with_source(context, self.source.clone())
    }
}

/// Instantiates the ordinary process-environment-backed Module.
#[lenso_native_adapter::module(
    descriptor = r#"{"provided_capabilities":[{"capability_id":"lenso.secrets@1","descriptor_version":"1.0.0","operations":["resolve"],"operation_kinds":{},"default_admission":{"queue_capacity":2,"max_concurrency":1},"operation_admissions":{},"event_admission":null,"cross_lane_transfer":false}],"required_capabilities":[]}"#,
    configuration_schema = "config.schema.json"
)]
fn instantiate(
    context: NativeModuleFactoryContext<'_>,
) -> Result<NativeModuleInstance, RuntimeFailure> {
    instantiate_with_source(context, Rc::new(ProcessEnvironment))
}

fn instantiate_with_source(
    context: NativeModuleFactoryContext<'_>,
    source: Rc<dyn SecretSource>,
) -> Result<NativeModuleInstance, RuntimeFailure> {
    if context.entrypoint() != "default" {
        return Err(RuntimeFailure::InvalidResolvedPlan {
            detail: "unsupported Env Secrets Module entrypoint".to_owned(),
        });
    }
    let config =
        serde_json::from_str::<EnvSecretsConfig>(context.configuration()).map_err(|error| {
            RuntimeFailure::InvalidResolvedPlan {
                detail: format!("Env Secrets Module configuration is invalid: {error}"),
            }
        })?;
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: format!("Env Secrets Module configuration is invalid: {error}"),
        })?;
    let provider = EnvSecretsProvider::new(config, source);
    let endpoint = Rc::new(SecretsEndpoint::new(provider.clone())) as Rc<dyn NativeRequestEndpoint>;
    Ok(NativeModuleInstance::with_lifecycle(
        vec![endpoint],
        EnvSecretsLifecycle { provider },
    ))
}

#[derive(Clone)]
struct EnvSecretsProvider {
    config: Rc<EnvSecretsConfig>,
    source: Rc<dyn SecretSource>,
}

impl EnvSecretsProvider {
    fn new(config: EnvSecretsConfig, source: Rc<dyn SecretSource>) -> Self {
        Self {
            config: Rc::new(config),
            source,
        }
    }

    fn verify_sources(&self) -> Result<(), RuntimeFailure> {
        for reference in self.config.sources.keys() {
            self.read(reference)?;
        }
        Ok(())
    }

    fn read(&self, reference: &str) -> Result<String, RuntimeFailure> {
        let source = self
            .config
            .source_for(reference)
            .ok_or_else(|| RuntimeFailure::Internal {
                detail: "Env Secrets attempted to read an unbound reference".to_owned(),
            })?;
        self.source
            .read(source)
            .map_err(|SourceUnavailable| RuntimeFailure::ModuleFailure {
                detail: format!("configured secret reference `{reference}` is unavailable"),
            })
    }
}

impl fmt::Debug for EnvSecretsProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvSecretsProvider")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl SecretsProvider for EnvSecretsProvider {
    fn resolve(
        &self,
        _context: InvocationContext,
        request: ResolveRequest,
    ) -> NativeRequestFuture<Secrets> {
        let result = if !valid_reference(&request.reference) {
            Err(SecretsInvocationError::Domain(
                ResolveError::InvalidReference,
            ))
        } else if self.config.source_for(&request.reference).is_none() {
            Err(SecretsInvocationError::Domain(
                ResolveError::UnknownReference,
            ))
        } else {
            self.read(&request.reference)
                .map(|value| ResolveResponse { value })
                .map_err(SecretsInvocationError::Runtime)
        };
        let result = match result {
            Ok(response) => Ok(Ok(response)),
            Err(SecretsInvocationError::Domain(error)) => Ok(Err(error)),
            Err(SecretsInvocationError::Runtime(error)) => Err(error),
        };
        Box::pin(futures::future::ready(result))
    }
}

#[derive(Debug)]
struct EnvSecretsLifecycle {
    provider: EnvSecretsProvider,
}

impl ModuleLifecycle for EnvSecretsLifecycle {
    fn prepare(&self, _context: PrepareContext) -> ModuleFuture {
        Box::pin(futures::future::ready(self.provider.verify_sources()))
    }
}

trait SecretSource: fmt::Debug + 'static {
    fn read(&self, environment_variable: &str) -> Result<String, SourceUnavailable>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceUnavailable;

#[derive(Debug)]
struct ProcessEnvironment;

impl SecretSource for ProcessEnvironment {
    fn read(&self, environment_variable: &str) -> Result<String, SourceUnavailable> {
        std::env::var(environment_variable).map_err(|_| SourceUnavailable)
    }
}

fn deserialize_unique_sources<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct UniqueSources;

    impl<'de> serde::de::Visitor<'de> for UniqueSources {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a logical-reference to environment-variable map")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut sources = BTreeMap::new();
            while let Some((reference, source)) = access.next_entry::<String, String>()? {
                if sources.insert(reference.clone(), source).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate logical secret reference `{reference}`"
                    )));
                }
            }
            Ok(sources)
        }
    }

    deserializer.deserialize_map(UniqueSources)
}

fn valid_reference(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= MAX_REFERENCE_LENGTH
        && !reference.starts_with('/')
        && !reference.ends_with('/')
        && !reference.contains("//")
        && reference
            .split('/')
            .all(|segment| segment != "." && segment != "..")
        && reference
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
}

fn valid_environment_variable(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests;
