# Lenso Secrets context

`lenso-secrets-module` owns protocol-neutral secret resolution and concrete
Secrets Provider Modules. Consumers depend only on `lenso.secrets@1` and are
bound to one exact Provider before boot.

The Env Provider owns no secret values. Its immutable configuration contains
only logical references and environment-variable names. Preparation verifies
that every configured source is available without retaining its value. Each
resolution reads the selected source again, so the Module never creates a
second durable authority.

Missing configured sources are Runtime Failures. Malformed references and
well-formed but unbound references are typed Domain Errors. No failure text or
diagnostic contains a resolved value.
