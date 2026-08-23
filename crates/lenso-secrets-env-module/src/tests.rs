use std::{cell::RefCell, collections::BTreeMap, rc::Rc, time::Duration};

use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    ModuleInstancePlan, ResolvedAppPlan,
};
use lenso_capability_secrets::{
    CAPABILITY_ID, DESCRIPTOR_VERSION, RESOLVE_OPERATION, ResolveError, ResolveRequest, Secrets,
};
use lenso_kernel::{DeterministicDriver, Kernel, RuntimeFailure, ShutdownOutcome};
use lenso_native_adapter::{
    NativeModuleFactory, NativeModuleFactoryContext, NativeModuleInstance, NativeModuleRegistry,
};

use super::{
    EnvSecretsConfig, EnvSecretsConfigError, EnvSecretsFactory, PACKAGE_ID, SecretSource,
    SourceUnavailable,
};

const CALLER_PACKAGE_ID: &str = "test.secrets-caller";

#[derive(Debug)]
struct CallerFactory;

impl NativeModuleFactory for CallerFactory {
    fn package_id(&self) -> &'static str {
        CALLER_PACKAGE_ID
    }

    fn instantiate(
        &self,
        _context: NativeModuleFactoryContext<'_>,
    ) -> Result<NativeModuleInstance, RuntimeFailure> {
        Ok(NativeModuleInstance::default())
    }
}

#[derive(Clone, Debug, Default)]
struct MutableSource {
    values: Rc<RefCell<BTreeMap<String, String>>>,
}

impl MutableSource {
    fn insert(&self, name: &str, value: &str) {
        self.values
            .borrow_mut()
            .insert(name.to_owned(), value.to_owned());
    }

    fn remove(&self, name: &str) {
        self.values.borrow_mut().remove(name);
    }
}

impl SecretSource for MutableSource {
    fn read(&self, environment_variable: &str) -> Result<String, SourceUnavailable> {
        self.values
            .borrow()
            .get(environment_variable)
            .cloned()
            .ok_or(SourceUnavailable)
    }
}

fn config() -> EnvSecretsConfig {
    EnvSecretsConfig::new()
        .with_reference("database/url", "APP_DATABASE_URL")
        .expect("test mapping should be valid")
}

fn plan(config: &EnvSecretsConfig) -> ResolvedAppPlan {
    plan_with_configuration(serde_json::to_string(config).expect("config should serialize"))
}

fn plan_with_configuration(configuration: String) -> ResolvedAppPlan {
    let caller = ModuleInstancePlan::new("caller", CALLER_PACKAGE_ID).with_requirement(
        CapabilityRequirementPlan::one(CAPABILITY_ID, DESCRIPTOR_VERSION),
    );
    let secrets = ModuleInstancePlan::new("secrets", PACKAGE_ID)
        .with_configuration(configuration)
        .with_capability(CapabilityEndpointPlan::new(
            CAPABILITY_ID,
            DESCRIPTOR_VERSION,
            [RESOLVE_OPERATION],
        ));
    AppComposition::new(
        vec![caller, secrets],
        vec![CapabilityBinding::new(
            "caller",
            CAPABILITY_ID,
            DESCRIPTOR_VERSION,
            "secrets",
        )],
    )
    .resolve()
    .expect("Secrets test Composition should resolve")
}

#[test]
fn invalid_plan_configuration_fails_before_preparation() {
    let driver = DeterministicDriver::new();
    let result = driver.run(Kernel::start_native(
        plan_with_configuration(
            serde_json::json!({"references": {"../database": "APP_DATABASE_URL"}}).to_string(),
        ),
        driver.clone(),
        NativeModuleRegistry::new()
            .with_factory(CallerFactory)
            .with_factory(EnvSecretsFactory::with_source(Rc::new(
                MutableSource::default(),
            ))),
    ));

    assert!(matches!(
        result,
        Err(RuntimeFailure::InvalidResolvedPlan { detail })
            if detail.contains("invalid logical secret reference")
    ));
}

#[test]
fn duplicate_plan_references_are_rejected_instead_of_overwritten() {
    let driver = DeterministicDriver::new();
    let result = driver.run(Kernel::start_native(
        plan_with_configuration(
            r#"{"references":{"database/url":"FIRST_URL","database/url":"SECOND_URL"}}"#.to_owned(),
        ),
        driver.clone(),
        NativeModuleRegistry::new()
            .with_factory(CallerFactory)
            .with_factory(EnvSecretsFactory::with_source(Rc::new(
                MutableSource::default(),
            ))),
    ));

    assert!(matches!(
        result,
        Err(RuntimeFailure::InvalidResolvedPlan { detail })
            if detail.contains("duplicate logical secret reference")
    ));
}

#[test]
fn configured_secret_resolves_and_source_rotation_is_observed() {
    let source = MutableSource::default();
    source.insert("APP_DATABASE_URL", "postgres://first");
    let config = config();
    let factory = EnvSecretsFactory::with_source(Rc::new(source.clone()));
    let driver = DeterministicDriver::new();
    let app = driver
        .run(Kernel::start_native(
            plan(&config),
            driver.clone(),
            NativeModuleRegistry::new()
                .with_factory(CallerFactory)
                .with_factory(factory),
        ))
        .expect("configured source should prepare the App");

    let first = driver
        .run(app.invoke::<Secrets>(
            "caller",
            RESOLVE_OPERATION,
            ResolveRequest {
                reference: "database/url".to_owned(),
            },
        ))
        .expect("resolved binding should be available")
        .expect("configured reference should resolve");
    assert_eq!(first.value, "postgres://first");
    assert!(!format!("{first:?}").contains("postgres://first"));

    source.insert("APP_DATABASE_URL", "postgres://rotated");
    let rotated = driver
        .run(app.invoke::<Secrets>(
            "caller",
            RESOLVE_OPERATION,
            ResolveRequest {
                reference: "database/url".to_owned(),
            },
        ))
        .expect("resolved binding should stay available")
        .expect("configured reference should resolve after rotation");
    assert_eq!(rotated.value, "postgres://rotated");
    assert_eq!(
        driver.run(app.shutdown(Duration::from_secs(1))),
        ShutdownOutcome::Clean
    );
}

#[test]
fn invalid_and_unknown_references_are_distinct_domain_errors() {
    let source = MutableSource::default();
    source.insert("APP_DATABASE_URL", "secret-value");
    let config = config();
    let driver = DeterministicDriver::new();
    let app = driver
        .run(Kernel::start_native(
            plan(&config),
            driver.clone(),
            NativeModuleRegistry::new()
                .with_factory(CallerFactory)
                .with_factory(EnvSecretsFactory::with_source(Rc::new(source))),
        ))
        .unwrap();

    let invalid = driver
        .run(app.invoke::<Secrets>(
            "caller",
            RESOLVE_OPERATION,
            ResolveRequest {
                reference: "../database".to_owned(),
            },
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(invalid, ResolveError::InvalidReference);
    let unknown = driver
        .run(app.invoke::<Secrets>(
            "caller",
            RESOLVE_OPERATION,
            ResolveRequest {
                reference: "payments/key".to_owned(),
            },
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(unknown, ResolveError::UnknownReference);
    assert_eq!(
        driver.run(app.shutdown(Duration::from_secs(1))),
        ShutdownOutcome::Clean
    );
}

#[test]
fn missing_required_source_fails_preparation_without_leaking_source_details() {
    let driver = DeterministicDriver::new();
    let config = config();
    let result = driver.run(Kernel::start_native(
        plan(&config),
        driver.clone(),
        NativeModuleRegistry::new()
            .with_factory(CallerFactory)
            .with_factory(EnvSecretsFactory::with_source(Rc::new(
                MutableSource::default(),
            ))),
    ));

    assert!(matches!(
        result,
        Err(RuntimeFailure::ModuleFailure { detail })
            if detail.contains("database/url")
                && !detail.contains("APP_DATABASE_URL")
                && !detail.contains("secret-value")
    ));
}

#[test]
fn runtime_source_loss_is_truthful_and_does_not_fallback() {
    let source = MutableSource::default();
    source.insert("APP_DATABASE_URL", "secret-value");
    let config = config();
    let driver = DeterministicDriver::new();
    let app = driver
        .run(Kernel::start_native(
            plan(&config),
            driver.clone(),
            NativeModuleRegistry::new()
                .with_factory(CallerFactory)
                .with_factory(EnvSecretsFactory::with_source(Rc::new(source.clone()))),
        ))
        .unwrap();
    source.remove("APP_DATABASE_URL");

    let error = driver
        .run(app.invoke::<Secrets>(
            "caller",
            RESOLVE_OPERATION,
            ResolveRequest {
                reference: "database/url".to_owned(),
            },
        ))
        .expect_err("lost source must be a Runtime Failure");
    assert!(matches!(
        error,
        RuntimeFailure::ModuleFailure { detail }
            if detail.contains("database/url") && !detail.contains("secret-value")
    ));
}

#[test]
fn configuration_rejects_invalid_or_duplicate_mappings() {
    let mut config = EnvSecretsConfig::new();
    assert_eq!(config.validate(), Err(EnvSecretsConfigError::Empty));
    assert_eq!(
        config.insert("../database", "APP_DATABASE_URL"),
        Err(EnvSecretsConfigError::InvalidReference)
    );
    assert_eq!(
        config.insert("database/url", "not-portable-name"),
        Err(EnvSecretsConfigError::InvalidEnvironmentVariable)
    );
    config.insert("database/url", "APP_DATABASE_URL").unwrap();
    assert_eq!(
        config.insert("database/url", "OTHER_DATABASE_URL"),
        Err(EnvSecretsConfigError::DuplicateReference)
    );
    assert_eq!(config.len(), 1);
    assert!(!config.is_empty());
}
