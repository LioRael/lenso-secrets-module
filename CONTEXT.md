# Lenso Secrets context

`lenso-secrets-plugin` owns protocol-neutral secret resolution and concrete
Secrets Provider Plugins. Consumers depend only on `lenso.secrets@1` and are
bound to one exact Provider before boot.

Provider configuration contains only logical references and provider-local
source names. Preparation verifies that every configured source is available
without retaining its value. Each resolution reads the selected source again,
so the Plugin never creates a second durable authority. The concrete Providers
are environment variables, macOS Keychain, a standard age-encrypted local
file, and a bounded trusted command for remote Secret Manager CLIs.

Missing configured sources are Runtime Failures. Malformed references and
well-formed but unbound references are typed Domain Errors. No failure text or
diagnostic contains a resolved value.
