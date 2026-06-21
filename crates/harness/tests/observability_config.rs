use sondera_harness::observability::{
    EnvMap, ObservabilityConfig, ObservabilityOptions, OtelProtocol,
};

#[test]
fn observability_disabled_without_flag_or_env() {
    let config = ObservabilityConfig::from_options_and_env(
        ObservabilityOptions::default(),
        &EnvMap::default(),
    );

    assert!(!config.enabled);
    assert!(!config.metrics_enabled);
    assert_eq!(config.endpoint, None);
    assert_eq!(config.service_name, "sondera-harness");
}

#[test]
fn observability_enabled_by_cli_flag() {
    let config = ObservabilityConfig::from_options_and_env(
        ObservabilityOptions {
            enabled: true,
            ..Default::default()
        },
        &EnvMap::default(),
    );

    assert!(config.enabled);
}

#[test]
fn observability_enabled_by_otlp_endpoint_env() {
    let env = EnvMap::from_pairs([("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")]);
    let config = ObservabilityConfig::from_options_and_env(ObservabilityOptions::default(), &env);

    assert!(config.enabled);
    assert_eq!(config.endpoint.as_deref(), Some("http://localhost:4317"));
}

#[test]
fn cli_values_override_environment_values() {
    let env = EnvMap::from_pairs([
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env:4317"),
        ("OTEL_SERVICE_NAME", "env-service"),
    ]);
    let config = ObservabilityConfig::from_options_and_env(
        ObservabilityOptions {
            endpoint: Some("http://cli:4317".to_string()),
            service_name: Some("cli-service".to_string()),
            protocol: OtelProtocol::Http,
            ..Default::default()
        },
        &env,
    );

    assert!(config.enabled);
    assert_eq!(config.endpoint.as_deref(), Some("http://cli:4317"));
    assert_eq!(config.service_name, "cli-service");
    assert_eq!(config.protocol, OtelProtocol::Http);
}

#[test]
fn metrics_are_disabled_until_explicitly_enabled() {
    let env = EnvMap::from_pairs([("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")]);
    let traces_only =
        ObservabilityConfig::from_options_and_env(ObservabilityOptions::default(), &env);
    let with_metrics = ObservabilityConfig::from_options_and_env(
        ObservabilityOptions {
            metrics_enabled: true,
            ..Default::default()
        },
        &env,
    );

    assert!(!traces_only.metrics_enabled);
    assert!(with_metrics.metrics_enabled);
}
