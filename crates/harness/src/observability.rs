use crate::{Adjudicated, Decision, Event, TrajectoryEvent};
use anyhow::Result;
use clap::ValueEnum;
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{Resource, metrics::SdkMeterProvider, trace::SdkTracerProvider};
use std::collections::HashMap;
use std::time::Duration;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

const DEFAULT_SERVICE_NAME: &str = "sondera-harness";

pub const HTTP_ADJUDICATE_ROUTE: HttpRouteTelemetry =
    HttpRouteTelemetry::new("POST", "/api/adjudicate", "adjudicate");
pub const HTTP_LIST_ESCALATIONS_ROUTE: HttpRouteTelemetry =
    HttpRouteTelemetry::new("GET", "/api/escalations", "list_escalations");
pub const HTTP_STREAM_ESCALATIONS_ROUTE: HttpRouteTelemetry =
    HttpRouteTelemetry::new("GET", "/api/escalations/stream", "stream_escalations");
pub const HTTP_GET_ESCALATION_ROUTE: HttpRouteTelemetry =
    HttpRouteTelemetry::new("GET", "/api/escalations/{id}", "get_escalation");
pub const HTTP_APPROVE_ESCALATION_ROUTE: HttpRouteTelemetry =
    HttpRouteTelemetry::new("POST", "/api/escalations/{id}/approve", "approve_escalation");
pub const HTTP_DENY_ESCALATION_ROUTE: HttpRouteTelemetry =
    HttpRouteTelemetry::new("POST", "/api/escalations/{id}/deny", "deny_escalation");

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum OtelProtocol {
    #[default]
    Grpc,
    Http,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservabilityOptions {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub protocol: OtelProtocol,
    pub service_name: Option<String>,
    pub metrics_enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservabilityConfig {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub protocol: OtelProtocol,
    pub service_name: String,
    pub metrics_enabled: bool,
}

pub trait EnvSource {
    fn get(&self, key: &str) -> Option<String>;
}

#[derive(Clone, Debug, Default)]
pub struct EnvMap {
    values: HashMap<String, String>,
}

impl EnvMap {
    pub fn from_pairs<const N: usize>(pairs: [(&str, &str); N]) -> Self {
        let values = pairs
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        Self { values }
    }
}

impl EnvSource for EnvMap {
    fn get(&self, key: &str) -> Option<String> {
        self.values.get(key).cloned()
    }
}

pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

impl ObservabilityConfig {
    pub fn from_options_and_env(options: ObservabilityOptions, env: &impl EnvSource) -> Self {
        let endpoint = options
            .endpoint
            .or_else(|| env.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"))
            .or_else(|| env.get("OTEL_EXPORTER_OTLP_ENDPOINT"));
        let service_name = options
            .service_name
            .or_else(|| env.get("OTEL_SERVICE_NAME"))
            .unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_string());
        let enabled = options.enabled || endpoint.is_some();

        Self {
            enabled,
            endpoint,
            protocol: options.protocol,
            service_name,
            metrics_enabled: options.metrics_enabled,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventTelemetry {
    pub event_id: String,
    pub trajectory_id: String,
    pub agent_id: String,
    pub agent_provider: String,
    pub category: &'static str,
    pub event_type: &'static str,
}

impl EventTelemetry {
    pub fn from_event(event: &Event) -> Self {
        let (category, event_type) = event_type_names(&event.event);
        Self {
            event_id: event.event_id.clone(),
            trajectory_id: event.trajectory_id.clone(),
            agent_id: event.agent.id.clone(),
            agent_provider: event.agent.provider_id.clone(),
            category,
            event_type,
        }
    }

    pub fn policy_ids(adjudicated: &Adjudicated) -> Vec<String> {
        adjudicated
            .annotations
            .iter()
            .filter_map(|annotation| annotation.policy_id.clone())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpRouteTelemetry {
    pub method: &'static str,
    pub route: &'static str,
    pub operation: &'static str,
}

impl HttpRouteTelemetry {
    pub const fn new(
        method: &'static str,
        route: &'static str,
        operation: &'static str,
    ) -> Self {
        Self {
            method,
            route,
            operation,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdjudicationMetricLabels {
    pub engine: String,
    pub decision: &'static str,
    pub agent_provider: String,
    pub event_category: &'static str,
    pub event_type: &'static str,
}

impl AdjudicationMetricLabels {
    pub fn new(engine: impl Into<String>, decision: Decision, event: &Event) -> Self {
        let telemetry = EventTelemetry::from_event(event);
        Self {
            engine: engine.into(),
            decision: decision_name(decision),
            agent_provider: telemetry.agent_provider,
            event_category: telemetry.category,
            event_type: telemetry.event_type,
        }
    }

    fn key_values(&self) -> Vec<KeyValue> {
        vec![
            KeyValue::new("engine", self.engine.clone()),
            KeyValue::new("decision", self.decision),
            KeyValue::new("agent_provider", self.agent_provider.clone()),
            KeyValue::new("event_category", self.event_category),
            KeyValue::new("event_type", self.event_type),
        ]
    }
}

pub struct ObservabilityGuard {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
}

impl ObservabilityGuard {
    fn disabled() -> Self {
        Self {
            tracer_provider: None,
            meter_provider: None,
        }
    }

    pub fn shutdown(&mut self) {
        if let Some(provider) = self.meter_provider.take() {
            let _ = provider.shutdown();
        }
        if let Some(provider) = self.tracer_provider.take() {
            let _ = provider.shutdown();
        }
    }
}

impl Drop for ObservabilityGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn init(config: &ObservabilityConfig, verbose: bool) -> Result<ObservabilityGuard> {
    let filter = if verbose {
        tracing_subscriber::EnvFilter::new("info,tarpc=warn,sondera=debug")
    } else {
        tracing_subscriber::EnvFilter::new("warn")
    };

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_span_events(FmtSpan::CLOSE);

    if !config.enabled {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .try_init()?;
        return Ok(ObservabilityGuard::disabled());
    }

    let resource = Resource::builder()
        .with_service_name(config.service_name.clone())
        .build();
    let tracer_provider = build_tracer_provider(config, resource.clone())?;
    let tracer =
        opentelemetry::trace::TracerProvider::tracer(&tracer_provider, config.service_name.clone());
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    let meter_provider = if config.metrics_enabled {
        let provider = build_meter_provider(config, resource)?;
        global::set_meter_provider(provider.clone());
        Some(provider)
    } else {
        None
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()?;

    Ok(ObservabilityGuard {
        tracer_provider: Some(tracer_provider),
        meter_provider,
    })
}

pub fn record_adjudication_metrics(
    engine: &str,
    decision: Decision,
    event: &Event,
    duration: Duration,
) {
    let labels = AdjudicationMetricLabels::new(engine, decision, event);
    let key_values = labels.key_values();
    let meter = global::meter("sondera-harness");

    meter
        .u64_counter("sondera_adjudications_total")
        .with_description("Total adjudications by decision and event type")
        .build()
        .add(1, &key_values);
    meter
        .f64_histogram("sondera_adjudication_duration_ms")
        .with_description("Adjudication duration in milliseconds")
        .build()
        .record(duration.as_secs_f64() * 1000.0, &key_values);
}

fn build_tracer_provider(
    config: &ObservabilityConfig,
    resource: Resource,
) -> Result<SdkTracerProvider> {
    let exporter = match config.protocol {
        OtelProtocol::Grpc => {
            let mut builder = opentelemetry_otlp::SpanExporter::builder().with_tonic();
            if let Some(endpoint) = &config.endpoint {
                builder = builder.with_endpoint(endpoint);
            }
            builder.build()?
        }
        OtelProtocol::Http => {
            let mut builder = opentelemetry_otlp::SpanExporter::builder().with_http();
            if let Some(endpoint) = &config.endpoint {
                builder = builder.with_endpoint(endpoint);
            }
            builder.build()?
        }
    };

    Ok(SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build())
}

fn build_meter_provider(
    config: &ObservabilityConfig,
    resource: Resource,
) -> Result<SdkMeterProvider> {
    let exporter = match config.protocol {
        OtelProtocol::Grpc => {
            let mut builder = opentelemetry_otlp::MetricExporter::builder().with_tonic();
            if let Some(endpoint) = &config.endpoint {
                builder = builder.with_endpoint(endpoint);
            }
            builder.build()?
        }
        OtelProtocol::Http => {
            let mut builder = opentelemetry_otlp::MetricExporter::builder().with_http();
            if let Some(endpoint) = &config.endpoint {
                builder = builder.with_endpoint(endpoint);
            }
            builder.build()?
        }
    };

    Ok(SdkMeterProvider::builder()
        .with_resource(resource)
        .with_periodic_exporter(exporter)
        .build())
}

pub fn decision_name(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "Allow",
        Decision::Deny => "Deny",
        Decision::Escalate => "Escalate",
    }
}

fn event_type_names(event: &TrajectoryEvent) -> (&'static str, &'static str) {
    match event {
        TrajectoryEvent::Action(action) => {
            let event_type = match action {
                crate::Action::ToolCall(_) => "ToolCall",
                crate::Action::ShellCommand(_) => "ShellCommand",
                crate::Action::WebFetch(_) => "WebFetch",
                crate::Action::FileOperation(_) => "FileOperation",
            };
            ("Action", event_type)
        }
        TrajectoryEvent::Observation(observation) => {
            let event_type = match observation {
                crate::Observation::Prompt(_) => "Prompt",
                crate::Observation::Think(_) => "Think",
                crate::Observation::ToolOutput(_) => "ToolOutput",
                crate::Observation::ShellCommandOutput(_) => "ShellCommandOutput",
                crate::Observation::WebFetchOutput(_) => "WebFetchOutput",
                crate::Observation::FileOperationResult(_) => "FileOperationResult",
            };
            ("Observation", event_type)
        }
        TrajectoryEvent::Control(control) => {
            let event_type = match control {
                crate::Control::Started(_) => "Started",
                crate::Control::Completed(_) => "Completed",
                crate::Control::Failed(_) => "Failed",
                crate::Control::Terminated(_) => "Terminated",
                crate::Control::Suspended(_) => "Suspended",
                crate::Control::Resumed(_) => "Resumed",
                crate::Control::Adjudicated(_) => "Adjudicated",
            };
            ("Control", event_type)
        }
        TrajectoryEvent::State(state) => {
            let event_type = match state {
                crate::State::Snapshot(_) => "Snapshot",
            };
            ("State", event_type)
        }
    }
}
