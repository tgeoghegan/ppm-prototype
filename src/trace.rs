use tracing_error::ErrorLayer;
use tracing_subscriber::{fmt, fmt::format::FmtSpan, layer::SubscriberExt, EnvFilter, Registry};

/// Configures and installs a tracing subscriber
pub fn install_subscriber() {
    // Configure a tracing subscriber. The crate emits events using `info!`,
    // `err!`, etc. macros from crate `tracing`.
    let fmt_layer = fmt::layer()
        .with_span_events(FmtSpan::ENTER | FmtSpan::EXIT)
        .with_thread_ids(true)
        // TODO(timg): take an argument for pretty vs. full vs. compact vs. JSON
        // output
        .pretty()
        .with_level(true)
        .with_target(true);

    let subscriber = Registry::default()
        .with(fmt_layer)
        // Configure filters with RUST_LOG env var. Format discussed at
        // https://docs.rs/tracing-subscriber/0.2.20/tracing_subscriber/filter/struct.EnvFilter.html
        .with(EnvFilter::from_default_env())
        .with(ErrorLayer::default());

    tracing::subscriber::set_global_default(subscriber).unwrap();
}
