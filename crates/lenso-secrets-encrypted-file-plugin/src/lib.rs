//! Age-encrypted local-file Secrets Provider Plugin.

use std::{collections::BTreeMap, fmt, fs, io::Read, iter, path::PathBuf};

use age::secrecy::SecretString;
use lenso::prelude::*;
use lenso_capability_secrets::{self as secrets, ResolveError, ResolveRequest, ResolveResponse};
use lenso_kernel::RuntimeFailure;
use zeroize::{Zeroize, Zeroizing};

const MAX_REFERENCE_LENGTH: usize = 256;
const MAX_SOURCE_LENGTH: usize = 512;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedFileConfig {
    path: PathBuf,
    key_environment_variable: String,
    #[serde(deserialize_with = "deserialize_unique_references")]
    references: BTreeMap<String, String>,
    max_file_bytes: u64,
    max_plaintext_bytes: usize,
    max_records: usize,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDocument {
    version: u32,
    secrets: BTreeMap<String, String>,
}

impl Drop for FileDocument {
    fn drop(&mut self) {
        for value in self.secrets.values_mut() {
            value.zeroize();
        }
    }
}

fn validate_config(config: &EncryptedFileConfig) -> Result<(), RuntimeFailure> {
    if config.path.as_os_str().is_empty() {
        return Err(invalid_plan("encrypted secret file path is empty"));
    }
    if !valid_environment_variable(&config.key_environment_variable) {
        return Err(invalid_plan(
            "encrypted secret file key environment variable is invalid",
        ));
    }
    if config.references.is_empty() {
        return Err(invalid_plan(
            "encrypted secret file references must contain at least one mapping",
        ));
    }
    for (reference, source) in &config.references {
        if !valid_reference(reference) {
            return Err(invalid_plan(
                "encrypted secret file logical reference is invalid",
            ));
        }
        if !valid_source_name(source) {
            return Err(invalid_plan("encrypted secret file source name is invalid"));
        }
    }
    if !(1..=MAX_FILE_BYTES).contains(&config.max_file_bytes) {
        return Err(invalid_plan(
            "max_file_bytes must be between 1 and 67108864",
        ));
    }
    if !(1..=MAX_PLAINTEXT_BYTES).contains(&config.max_plaintext_bytes) {
        return Err(invalid_plan(
            "max_plaintext_bytes must be between 1 and 16777216",
        ));
    }
    if !(1..=MAX_RECORDS).contains(&config.max_records) {
        return Err(invalid_plan("max_records must be between 1 and 100000"));
    }
    Ok(())
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "config.schema.json",
    validate = validate_config
)]
#[derive(Clone, Debug)]
struct EncryptedFileSecretsPlugin {
    #[config]
    config: EncryptedFileConfig,
}

impl Lifecycle for EncryptedFileSecretsPlugin {
    fn prepare(
        &self,
        _context: PrepareContext,
    ) -> impl std::future::Future<Output = Result<(), RuntimeFailure>> {
        std::future::ready(verify_sources(&self.config, &EnvironmentKeySource))
    }
}

#[lenso::provides(secrets::Secrets)]
impl EncryptedFileSecretsPlugin {
    fn resolve(
        &self,
        _context: Ctx,
        request: ResolveRequest,
    ) -> impl std::future::Future<Output = PluginResult<ResolveResponse, ResolveError>> {
        let ResolveRequest { reference } = request;
        futures::future::ready(resolve(&self.config, &EnvironmentKeySource, &reference))
    }
}

fn resolve(
    config: &EncryptedFileConfig,
    key_source: &dyn KeySource,
    reference: &str,
) -> PluginResult<ResolveResponse, ResolveError> {
    if !valid_reference(reference) {
        return Err(PluginError::domain(ResolveError::InvalidReference));
    }
    let source = config
        .references
        .get(reference)
        .ok_or_else(|| PluginError::domain(ResolveError::UnknownReference))?;
    let mut document = load_document(config, key_source).map_err(|()| {
        PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: format!(
                "configured encrypted-file secret reference `{reference}` is unavailable"
            ),
        })
    })?;
    let value = document.secrets.remove(source).ok_or_else(|| {
        PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: format!(
                "configured encrypted-file secret reference `{reference}` is unavailable"
            ),
        })
    })?;
    let value = Zeroizing::new(value);
    Ok(ResolveResponse {
        value: value.as_str().to_owned(),
    })
}

fn verify_sources(
    config: &EncryptedFileConfig,
    key_source: &dyn KeySource,
) -> Result<(), RuntimeFailure> {
    let document =
        load_document(config, key_source).map_err(|()| RuntimeFailure::PluginFailure {
            detail: "configured encrypted secret file is unavailable".to_owned(),
        })?;
    for (reference, source) in &config.references {
        if !document.secrets.contains_key(source) {
            return Err(RuntimeFailure::PluginFailure {
                detail: format!(
                    "configured encrypted-file secret reference `{reference}` is unavailable"
                ),
            });
        }
    }
    Ok(())
}

fn load_document(
    config: &EncryptedFileConfig,
    key_source: &dyn KeySource,
) -> Result<FileDocument, ()> {
    let metadata = fs::symlink_metadata(&config.path).map_err(|_| ())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(());
    }
    if metadata.len() == 0 || metadata.len() > config.max_file_bytes {
        return Err(());
    }
    let ciphertext = fs::read(&config.path).map_err(|_| ())?;
    if ciphertext.len() as u64 > config.max_file_bytes {
        return Err(());
    }
    let passphrase = key_source.read(&config.key_environment_variable)?;
    let decryptor = age::Decryptor::new(ciphertext.as_slice()).map_err(|_| ())?;
    let identity = age::scrypt::Identity::new(passphrase);
    let mut reader = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .map_err(|_| ())?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .by_ref()
        .take(config.max_plaintext_bytes as u64 + 1)
        .read_to_end(&mut plaintext)
        .map_err(|_| ())?;
    if plaintext.len() > config.max_plaintext_bytes {
        return Err(());
    }
    let document = serde_json::from_slice::<FileDocument>(&plaintext).map_err(|_| ())?;
    if document.version != 1
        || document.secrets.is_empty()
        || document.secrets.len() > config.max_records
        || document
            .secrets
            .iter()
            .any(|(name, value)| !valid_source_name(name) || value.is_empty())
    {
        return Err(());
    }
    Ok(document)
}

trait KeySource: fmt::Debug {
    fn read(&self, name: &str) -> Result<SecretString, ()>;
}

#[derive(Debug)]
struct EnvironmentKeySource;

impl KeySource for EnvironmentKeySource {
    fn read(&self, name: &str) -> Result<SecretString, ()> {
        std::env::var(name).map(SecretString::from).map_err(|_| ())
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

fn valid_environment_variable(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
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
            formatter.write_str("a logical-reference to encrypted-file key map")
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
    use std::io::Write;

    use super::*;

    #[derive(Debug)]
    struct FixedKeySource(&'static str);

    impl KeySource for FixedKeySource {
        fn read(&self, _name: &str) -> Result<SecretString, ()> {
            Ok(SecretString::from(self.0.to_owned()))
        }
    }

    fn write_document(path: &std::path::Path, passphrase: &str, value: &str) {
        let plaintext = serde_json::json!({
            "version": 1,
            "secrets": { "openai": value }
        })
        .to_string();
        let encryptor =
            age::Encryptor::with_user_passphrase(SecretString::from(passphrase.to_owned()));
        let mut ciphertext = Vec::new();
        let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
        writer.write_all(plaintext.as_bytes()).unwrap();
        writer.finish().unwrap();
        fs::write(path, ciphertext).unwrap();
    }

    fn config(path: PathBuf) -> EncryptedFileConfig {
        EncryptedFileConfig {
            path,
            key_environment_variable: "LENSO_SECRETS_FILE_PASSPHRASE".to_owned(),
            references: BTreeMap::from([("model/openai-api-key".to_owned(), "openai".to_owned())]),
            max_file_bytes: 1024 * 1024,
            max_plaintext_bytes: 1024 * 1024,
            max_records: 100,
        }
    }

    #[test]
    fn descriptor_exposes_one_secrets_provider() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(descriptor["plugin_id"], "lenso.secrets.encrypted-file");
        assert_eq!(
            descriptor["provided_capabilities"][0]["capability_id"],
            "lenso.secrets@1"
        );
    }

    #[test]
    fn resolves_rotation_from_a_standard_age_container_without_debug_leakage() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secrets.age");
        write_document(&path, "correct horse battery staple", "first-secret");
        let config = config(path.clone());
        let source = FixedKeySource("correct horse battery staple");
        verify_sources(&config, &source).unwrap();
        let first = resolve(&config, &source, "model/openai-api-key").unwrap();
        assert_eq!(first.value, "first-secret");
        assert!(!format!("{first:?}").contains("first-secret"));

        write_document(&path, "correct horse battery staple", "rotated-secret");
        let rotated = resolve(&config, &source, "model/openai-api-key").unwrap();
        assert_eq!(rotated.value, "rotated-secret");
    }

    #[test]
    fn wrong_key_tampering_and_missing_record_fail_without_secret_details() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secrets.age");
        write_document(&path, "correct passphrase", "never-log-this");
        let config = config(path.clone());
        let wrong = verify_sources(&config, &FixedKeySource("wrong passphrase")).unwrap_err();
        assert!(!format!("{wrong:?}").contains("never-log-this"));

        fs::write(&path, b"tampered").unwrap();
        let tampered = verify_sources(&config, &FixedKeySource("correct passphrase")).unwrap_err();
        assert!(!format!("{tampered:?}").contains("correct passphrase"));
    }

    #[test]
    fn rejects_symlinks_unknown_references_and_invalid_limits() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.age");
        write_document(&target, "passphrase", "secret");
        let mut config = config(target.clone());
        assert!(matches!(
            resolve(&config, &FixedKeySource("passphrase"), "unknown/reference"),
            Err(PluginError::Domain(ResolveError::UnknownReference))
        ));
        config.max_records = 0;
        assert!(validate_config(&config).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = directory.path().join("link.age");
            symlink(&target, &link).unwrap();
            config.max_records = 100;
            config.path = link;
            assert!(verify_sources(&config, &FixedKeySource("passphrase")).is_err());
        }
    }
}
