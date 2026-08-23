//! Explicit secret-reference resolution Capability.

include!("generated.rs");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_values_are_redacted_from_debug_output() {
        let response = ResolveResponse {
            value: "do-not-print".to_owned(),
        };

        assert!(!format!("{response:?}").contains("do-not-print"));
    }
}
