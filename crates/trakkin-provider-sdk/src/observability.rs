use std::{env, error::Error, io};

use tracing_subscriber::{
    EnvFilter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};

pub const PROVIDER_LOG_FILTER_ENV: &str = "TRAKKIN_PROVIDER_LOG";
pub const PROVIDER_LOG_FORMAT_ENV: &str = "TRAKKIN_PROVIDER_LOG_FORMAT";

pub fn init_provider_tracing(
    provider_id: &'static str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let filter = env::var(PROVIDER_LOG_FILTER_ENV).unwrap_or_else(|_| "info".to_owned());
    let filter = EnvFilter::try_new(filter)?;
    let format = env::var(PROVIDER_LOG_FORMAT_ENV).unwrap_or_else(|_| "json".to_owned());
    if format.eq_ignore_ascii_case("pretty") {
        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
                    .with_writer(io::stderr),
            )
            .try_init()?;
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_ansi(false)
                    .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
                    .with_writer(io::stderr),
            )
            .try_init()?;
    }
    tracing::info!(
        event = "provider.logging.initialized",
        provider.id = provider_id
    );
    Ok(())
}
