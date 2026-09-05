//! Indirect Host-style linkage set used to prove transitive Plugin retention.

/// Links every native Secrets Plugin through one Host-owned entry point.
pub fn link() {
    lenso_secrets_command_plugin::link();
    lenso_secrets_encrypted_file_plugin::link();
    lenso_secrets_env_plugin::link();
    lenso_secrets_keychain_plugin::link();
}
