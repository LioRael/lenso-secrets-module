//! Cross-crate linkage proof for the native Secrets Plugins.

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use lenso_native_adapter::NativePluginRegistry;

    #[test]
    fn explicit_link_anchors_retain_every_factory() {
        let descriptors = [
            lenso_secrets_command_plugin::link(),
            lenso_secrets_encrypted_file_plugin::link(),
            lenso_secrets_env_plugin::link(),
            lenso_secrets_keychain_plugin::link(),
        ];
        assert!(descriptors.iter().all(|descriptor| !descriptor.is_empty()));

        let package_ids = NativePluginRegistry::new()
            .with_linked_factories()
            .factories()
            .map(lenso_native_adapter::NativePluginFactory::package_id)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            package_ids,
            BTreeSet::from([
                "lenso.secrets.command",
                "lenso.secrets.encrypted-file",
                "lenso.secrets.env",
                "lenso.secrets.keychain",
            ])
        );
    }
}
