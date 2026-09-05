//! Allowlisted macOS Keychain Secrets Provider Plugin.

use std::{collections::BTreeMap, fmt};

use lenso::prelude::*;
use lenso_capability_secrets::{self as secrets, ResolveError, ResolveRequest, ResolveResponse};
use lenso_kernel::RuntimeFailure;
use secrecy::{ExposeSecret, SecretString};

const MAX_REFERENCE_LENGTH: usize = 256;
const MAX_SOURCE_LENGTH: usize = 512;

/// Keeps this Plugin's static factory registration linked into a Host binary.
#[inline(never)]
pub fn link() {
    __lenso_link_keychain_secrets_plugin();
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeychainConfig {
    service: String,
    #[serde(deserialize_with = "deserialize_unique_references")]
    references: BTreeMap<String, String>,
}

fn validate_config(config: &KeychainConfig) -> Result<(), RuntimeFailure> {
    if !valid_source_name(&config.service) {
        return Err(invalid_plan("Keychain service is invalid"));
    }
    if config.references.is_empty() {
        return Err(invalid_plan(
            "Keychain references must contain at least one mapping",
        ));
    }
    for (reference, account) in &config.references {
        if !valid_reference(reference) {
            return Err(invalid_plan("Keychain logical reference is invalid"));
        }
        if !valid_source_name(account) {
            return Err(invalid_plan("Keychain account is invalid"));
        }
    }
    Ok(())
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "config.schema.json",
    validate = validate_config
)]
#[derive(Clone, Debug)]
struct KeychainSecretsPlugin {
    #[config]
    config: KeychainConfig,
}

impl Lifecycle for KeychainSecretsPlugin {
    fn prepare(
        &self,
        _context: PrepareContext,
    ) -> impl std::future::Future<Output = Result<(), RuntimeFailure>> {
        std::future::ready(verify_sources(&self.config, &SystemKeychain))
    }
}

#[lenso::provides(secrets::Secrets)]
impl KeychainSecretsPlugin {
    fn resolve(
        &self,
        _context: Ctx,
        request: ResolveRequest,
    ) -> impl std::future::Future<Output = PluginResult<ResolveResponse, ResolveError>> {
        let ResolveRequest { reference } = request;
        futures::future::ready(resolve(&self.config, &SystemKeychain, &reference))
    }
}

fn resolve(
    config: &KeychainConfig,
    keychain: &dyn Keychain,
    reference: &str,
) -> PluginResult<ResolveResponse, ResolveError> {
    if !valid_reference(reference) {
        return Err(PluginError::domain(ResolveError::InvalidReference));
    }
    let account = config
        .references
        .get(reference)
        .ok_or_else(|| PluginError::domain(ResolveError::UnknownReference))?;
    let value = keychain.read(&config.service, account).map_err(|()| {
        PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: format!("configured Keychain secret reference `{reference}` is unavailable"),
        })
    })?;
    Ok(ResolveResponse {
        value: value.expose_secret().to_owned(),
    })
}

fn verify_sources(config: &KeychainConfig, keychain: &dyn Keychain) -> Result<(), RuntimeFailure> {
    for reference in config.references.keys() {
        resolve(config, keychain, reference).map_err(|error| match error {
            PluginError::Runtime(error) => error,
            PluginError::Domain(_) => RuntimeFailure::Internal {
                detail: "validated Keychain reference became invalid".to_owned(),
            },
        })?;
    }
    Ok(())
}

trait Keychain: fmt::Debug {
    fn read(&self, service: &str, account: &str) -> Result<SecretString, ()>;
}

#[derive(Debug)]
struct SystemKeychain;

#[cfg(target_os = "macos")]
impl Keychain for SystemKeychain {
    fn read(&self, service: &str, account: &str) -> Result<SecretString, ()> {
        let value = security_framework::passwords::get_generic_password(service, account)
            .map_err(|_| ())?;
        String::from_utf8(value)
            .map(SecretString::from)
            .map_err(|_| ())
    }
}

#[cfg(not(target_os = "macos"))]
impl Keychain for SystemKeychain {
    fn read(&self, _service: &str, _account: &str) -> Result<SecretString, ()> {
        Err(())
    }
}

fn valid_reference(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= MAX_REFERENCE_LENGTH
        && !reference.starts_with('/')
        && !reference.ends_with('/')
        && !reference.contains("//")
        && !reference.contains('\0')
        && reference
            .split('/')
            .all(|segment| segment != "." && segment != "..")
}

fn valid_source_name(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_SOURCE_LENGTH && !value.contains('\0')
}

fn deserialize_unique_references<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct UniqueReferences;

    impl<'de> serde::de::Visitor<'de> for UniqueReferences {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a logical-reference to Keychain-account map")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut references = BTreeMap::new();
            while let Some((reference, source)) = access.next_entry::<String, String>()? {
                if references.insert(reference.clone(), source).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate logical secret reference `{reference}`"
                    )));
                }
            }
            Ok(references)
        }
    }

    deserializer.deserialize_map(UniqueReferences)
}

fn invalid_plan(detail: impl Into<String>) -> RuntimeFailure {
    RuntimeFailure::InvalidResolvedPlan {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use super::*;

    #[derive(Clone, Debug, Default)]
    struct FakeKeychain {
        values: Rc<RefCell<BTreeMap<(String, String), SecretString>>>,
    }

    impl FakeKeychain {
        fn insert(&self, service: &str, account: &str, value: &str) {
            self.values.borrow_mut().insert(
                (service.to_owned(), account.to_owned()),
                SecretString::from(value.to_owned()),
            );
        }
    }

    impl Keychain for FakeKeychain {
        fn read(&self, service: &str, account: &str) -> Result<SecretString, ()> {
            self.values
                .borrow()
                .get(&(service.to_owned(), account.to_owned()))
                .map(|value| SecretString::from(value.expose_secret().to_owned()))
                .ok_or(())
        }
    }

    fn config() -> KeychainConfig {
        KeychainConfig {
            service: "com.lenso.agent".to_owned(),
            references: BTreeMap::from([("model/openai-api-key".to_owned(), "default".to_owned())]),
        }
    }

    #[test]
    fn descriptor_exposes_one_secrets_provider() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(descriptor["plugin_id"], "lenso.secrets.keychain");
        assert_eq!(
            descriptor["provided_capabilities"][0]["capability_id"],
            "lenso.secrets@1"
        );
    }

    #[test]
    fn resolves_rotation_without_retaining_or_debugging_the_secret() {
        let keychain = FakeKeychain::default();
        keychain.insert("com.lenso.agent", "default", "first-secret");
        let first = resolve(&config(), &keychain, "model/openai-api-key").unwrap();
        assert_eq!(first.value, "first-secret");
        assert!(!format!("{first:?}").contains("first-secret"));

        keychain.insert("com.lenso.agent", "default", "rotated-secret");
        let rotated = resolve(&config(), &keychain, "model/openai-api-key").unwrap();
        assert_eq!(rotated.value, "rotated-secret");
    }

    #[test]
    fn invalid_unknown_and_missing_sources_have_distinct_safe_failures() {
        let keychain = FakeKeychain::default();
        assert!(matches!(
            resolve(&config(), &keychain, "../invalid"),
            Err(PluginError::Domain(ResolveError::InvalidReference))
        ));
        assert!(matches!(
            resolve(&config(), &keychain, "unknown/reference"),
            Err(PluginError::Domain(ResolveError::UnknownReference))
        ));
        let error = verify_sources(&config(), &keychain).unwrap_err();
        let diagnostic = format!("{error:?}");
        assert!(diagnostic.contains("model/openai-api-key"));
        assert!(!diagnostic.contains("default"));
    }

    #[test]
    fn rejects_duplicate_and_malformed_configuration() {
        let duplicate = serde_json::from_str::<KeychainConfig>(
            r#"{"service":"com.lenso.agent","references":{"a":"one","a":"two"}}"#,
        )
        .unwrap_err();
        assert!(
            duplicate
                .to_string()
                .contains("duplicate logical secret reference")
        );

        let mut invalid = config();
        invalid.service = "\0".to_owned();
        assert!(validate_config(&invalid).is_err());
    }
}
