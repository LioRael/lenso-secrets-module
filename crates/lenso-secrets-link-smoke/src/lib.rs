//! Cross-crate linkage proof for the native Secrets Plugins.

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use lenso_native_adapter::NativePluginRegistry;

    #[test]
    fn explicit_link_anchors_retain_every_factory() {
        lenso_secrets_link_set::link();

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
