//! Bounded external-command Secrets Provider Plugin.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    env, fmt, fs,
    io::Read,
    path::PathBuf,
    process::{Child, Command, Stdio},
    rc::Rc,
    thread,
    time::{Duration, Instant},
};

use futures::channel::oneshot;
use lenso::prelude::*;
use lenso_capability_secrets::{self as secrets, ResolveError, ResolveRequest, ResolveResponse};
use lenso_kernel::RuntimeFailure;
use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, Zeroizing};

const SOURCE_PLACEHOLDER: &str = "{source}";
const MAX_REFERENCE_LENGTH: usize = 256;
const MAX_SOURCE_LENGTH: usize = 4096;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 65_536;
const MAX_ENVIRONMENT_NAMES: usize = 64;
const MAX_TIMEOUT_MS: u64 = 300_000;
const MAX_OUTPUT_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandConfig {
    program: PathBuf,
    arguments: Vec<String>,
    environment_allowlist: Vec<String>,
    #[serde(deserialize_with = "deserialize_unique_references")]
    references: BTreeMap<String, String>,
    timeout_ms: u64,
    max_output_bytes: usize,
}

#[derive(Clone, Debug)]
struct PreparedProgram {
    executable: PathBuf,
}

fn validate_config(config: &CommandConfig) -> Result<(), RuntimeFailure> {
    if !config.program.is_absolute() || config.program.as_os_str().is_empty() {
        return Err(invalid_plan("Secrets command program must be absolute"));
    }
    if config.arguments.is_empty() || config.arguments.len() > MAX_ARGUMENTS {
        return Err(invalid_plan(
            "Secrets command arguments must contain between 1 and 64 entries",
        ));
    }
    let argument_bytes = config
        .arguments
        .iter()
        .try_fold(0usize, |total, argument| {
            if argument.contains('\0') {
                None
            } else {
                total.checked_add(argument.len())
            }
        })
        .ok_or_else(|| invalid_plan("Secrets command arguments are invalid"))?;
    if argument_bytes > MAX_ARGUMENT_BYTES
        || config
            .arguments
            .iter()
            .filter(|argument| argument.as_str() == SOURCE_PLACEHOLDER)
            .count()
            != 1
        || config
            .arguments
            .iter()
            .any(|argument| argument.contains(SOURCE_PLACEHOLDER) && argument != SOURCE_PLACEHOLDER)
    {
        return Err(invalid_plan(
            "Secrets command arguments require exactly one standalone `{source}` placeholder",
        ));
    }
    if config.environment_allowlist.len() > MAX_ENVIRONMENT_NAMES {
        return Err(invalid_plan(
            "Secrets command environment allowlist cannot exceed 64 names",
        ));
    }
    let mut environment = BTreeSet::new();
    if config
        .environment_allowlist
        .iter()
        .any(|name| !valid_environment_variable(name) || !environment.insert(name))
    {
        return Err(invalid_plan(
            "Secrets command environment allowlist contains invalid or duplicate names",
        ));
    }
    if config.references.is_empty()
        || config
            .references
            .iter()
            .any(|(reference, source)| !valid_reference(reference) || !valid_source_name(source))
    {
        return Err(invalid_plan("Secrets command references are invalid"));
    }
    if !(1..=MAX_TIMEOUT_MS).contains(&config.timeout_ms) {
        return Err(invalid_plan("timeout_ms must be between 1 and 300000"));
    }
    if !(1..=MAX_OUTPUT_BYTES).contains(&config.max_output_bytes) {
        return Err(invalid_plan(
            "max_output_bytes must be between 1 and 1048576",
        ));
    }
    Ok(())
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "config.schema.json",
    validate = validate_config
)]
#[derive(Clone, Debug)]
struct CommandSecretsPlugin {
    #[config]
    config: CommandConfig,
    prepared: Rc<RefCell<Option<PreparedProgram>>>,
}

impl Lifecycle for CommandSecretsPlugin {
    async fn prepare(&self, _context: PrepareContext) -> Result<(), RuntimeFailure> {
        let executable = fs::canonicalize(&self.config.program)
            .map_err(|_| invalid_plan("Secrets command program is unavailable"))?;
        if !executable.is_file() {
            return Err(invalid_plan(
                "Secrets command program is not a regular file",
            ));
        }
        let prepared = PreparedProgram { executable };
        self.prepared.replace(Some(prepared.clone()));
        for (reference, source) in &self.config.references {
            run_resolver(&self.config, &prepared, source)
                .await
                .map_err(|()| RuntimeFailure::PluginFailure {
                    detail: format!(
                        "configured command secret reference `{reference}` is unavailable"
                    ),
                })?;
        }
        Ok(())
    }

    fn deactivate(
        &self,
        _context: DeactivateContext,
    ) -> impl std::future::Future<Output = Result<(), RuntimeFailure>> {
        self.prepared.replace(None);
        std::future::ready(Ok(()))
    }
}

#[lenso::provides(secrets::Secrets)]
impl CommandSecretsPlugin {
    async fn resolve(
        &self,
        _context: Ctx,
        request: ResolveRequest,
    ) -> PluginResult<ResolveResponse, ResolveError> {
        let ResolveRequest { reference } = request;
        if !valid_reference(&reference) {
            return Err(PluginError::domain(ResolveError::InvalidReference));
        }
        let source = self
            .config
            .references
            .get(&reference)
            .ok_or_else(|| PluginError::domain(ResolveError::UnknownReference))?;
        let prepared = self.prepared.borrow().clone().ok_or_else(|| {
            PluginError::runtime(RuntimeFailure::Unavailable {
                capability: secrets::CAPABILITY_ID,
            })
        })?;
        let value = run_resolver(&self.config, &prepared, source)
            .await
            .map_err(|()| {
                PluginError::runtime(RuntimeFailure::PluginFailure {
                    detail: format!(
                        "configured command secret reference `{reference}` is unavailable"
                    ),
                })
            })?;
        Ok(ResolveResponse {
            value: value.expose_secret().to_owned(),
        })
    }
}

async fn run_resolver(
    config: &CommandConfig,
    prepared: &PreparedProgram,
    source: &str,
) -> Result<SecretString, ()> {
    let request = CommandRequest {
        configured_program: config.program.clone(),
        executable: prepared.executable.clone(),
        arguments: config
            .arguments
            .iter()
            .map(|argument| {
                if argument == SOURCE_PLACEHOLDER {
                    source.to_owned()
                } else {
                    argument.clone()
                }
            })
            .collect(),
        environment_allowlist: config.environment_allowlist.clone(),
        timeout: Duration::from_millis(config.timeout_ms),
        max_output_bytes: config.max_output_bytes,
    };
    let (sender, receiver) = oneshot::channel();
    thread::Builder::new()
        .name("lenso-secret-resolver".to_owned())
        .spawn(move || {
            let result = run_command(request, &sender);
            let _ = sender.send(result);
        })
        .map_err(|_| ())?;
    receiver.await.map_err(|_| ())?
}

#[derive(Debug)]
struct CommandRequest {
    configured_program: PathBuf,
    executable: PathBuf,
    arguments: Vec<String>,
    environment_allowlist: Vec<String>,
    timeout: Duration,
    max_output_bytes: usize,
}

fn run_command(
    request: CommandRequest,
    cancellation: &oneshot::Sender<Result<SecretString, ()>>,
) -> Result<SecretString, ()> {
    let CommandRequest {
        configured_program,
        executable,
        arguments,
        environment_allowlist,
        timeout,
        max_output_bytes,
    } = request;
    if fs::canonicalize(&configured_program).map_err(|_| ())? != executable {
        return Err(());
    }
    let mut command = Command::new(&executable);
    command
        .args(&arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in &environment_allowlist {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command.spawn().map_err(|_| ())?;
    let stdout = child.stdout.take().ok_or(())?;
    let stderr = child.stderr.take().ok_or(())?;
    let stdout_reader = read_bounded(stdout, max_output_bytes);
    let stderr_reader = read_bounded(stderr, max_output_bytes);
    let status = wait_for_child(&mut child, timeout, cancellation)?;
    let stdout = stdout_reader.join().map_err(|_| ())??;
    let _stderr = stderr_reader.join().map_err(|_| ())??;
    if !status.success() || stdout.overflow {
        return Err(());
    }
    let mut value = String::from_utf8(stdout.bytes.to_vec()).map_err(|_| ())?;
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    if value.is_empty() {
        value.zeroize();
        return Err(());
    }
    Ok(SecretString::from(value))
}

fn wait_for_child(
    child: &mut Child,
    timeout: Duration,
    cancellation: &oneshot::Sender<Result<SecretString, ()>>,
) -> Result<std::process::ExitStatus, ()> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|_| ())? {
            return Ok(status);
        }
        if started.elapsed() >= timeout || cancellation.is_canceled() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[derive(Debug)]
struct BoundedOutput {
    bytes: Zeroizing<Vec<u8>>,
    overflow: bool,
}

fn read_bounded(
    mut reader: impl Read + Send + 'static,
    limit: usize,
) -> thread::JoinHandle<Result<BoundedOutput, ()>> {
    thread::spawn(move || {
        let mut bytes = Zeroizing::new(Vec::new());
        let mut buffer = [0u8; 8192];
        let mut overflow = false;
        loop {
            let read = reader.read(&mut buffer).map_err(|_| ())?;
            if read == 0 {
                break;
            }
            let remaining = limit.saturating_sub(bytes.len());
            let retained = remaining.min(read);
            bytes.extend_from_slice(&buffer[..retained]);
            overflow |= retained < read;
            buffer[..read].zeroize();
        }
        buffer.zeroize();
        Ok(BoundedOutput { bytes, overflow })
    })
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
            formatter.write_str("a logical-reference to command-source map")
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

#[cfg(all(test, unix))]
mod tests {
    use std::{io::Write, os::unix::fs::PermissionsExt, path::Path};

    use super::*;

    fn script(path: &Path, body: &str) {
        let mut file = fs::File::create(path).unwrap();
        writeln!(file, "#!/bin/sh").unwrap();
        writeln!(file, "{body}").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn config(program: PathBuf) -> CommandConfig {
        CommandConfig {
            program,
            arguments: vec![SOURCE_PLACEHOLDER.to_owned()],
            environment_allowlist: Vec::new(),
            references: BTreeMap::from([(
                "model/openai-api-key".to_owned(),
                "op://vault/item/password".to_owned(),
            )]),
            timeout_ms: 2_000,
            max_output_bytes: 4096,
        }
    }

    #[test]
    fn descriptor_exposes_one_secrets_provider() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(descriptor["plugin_id"], "lenso.secrets.command");
        assert_eq!(
            descriptor["provided_capabilities"][0]["capability_id"],
            "lenso.secrets@1"
        );
    }

    #[test]
    fn command_observes_rotation_and_strips_only_one_line_ending() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("resolver");
        script(&program, r"printf 'first-secret\n'");
        let config = config(program.clone());
        let prepared = PreparedProgram {
            executable: fs::canonicalize(&program).unwrap(),
        };
        let first = futures::executor::block_on(run_resolver(
            &config,
            &prepared,
            "op://vault/item/password",
        ))
        .unwrap();
        assert_eq!(first.expose_secret(), "first-secret");
        assert!(!format!("{first:?}").contains("first-secret"));

        script(&program, r"printf 'rotated-secret'");
        let rotated = futures::executor::block_on(run_resolver(
            &config,
            &prepared,
            "op://vault/item/password",
        ))
        .unwrap();
        assert_eq!(rotated.expose_secret(), "rotated-secret");
    }

    #[test]
    fn stderr_nonzero_timeout_and_output_overflow_are_redacted() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("resolver");
        let mut config = config(program.clone());
        script(&program, "echo never-log-this >&2; exit 7");
        let prepared = PreparedProgram {
            executable: fs::canonicalize(&program).unwrap(),
        };
        let failure = futures::executor::block_on(run_resolver(&config, &prepared, "source"));
        assert!(failure.is_err());
        assert!(!format!("{failure:?}").contains("never-log-this"));

        script(&program, "sleep 1; printf secret");
        config.timeout_ms = 10;
        assert!(futures::executor::block_on(run_resolver(&config, &prepared, "source")).is_err());

        script(&program, "printf 123456789");
        config.timeout_ms = 2_000;
        config.max_output_bytes = 4;
        assert!(futures::executor::block_on(run_resolver(&config, &prepared, "source")).is_err());
    }

    #[test]
    fn configuration_requires_absolute_program_and_one_standalone_placeholder() {
        let mut invalid = config(PathBuf::from("relative"));
        assert!(validate_config(&invalid).is_err());
        invalid.program = PathBuf::from("/absolute/resolver");
        invalid.arguments = vec!["prefix-{source}".to_owned()];
        assert!(validate_config(&invalid).is_err());
        invalid.arguments = vec![SOURCE_PLACEHOLDER.to_owned(), SOURCE_PLACEHOLDER.to_owned()];
        assert!(validate_config(&invalid).is_err());
    }
}
