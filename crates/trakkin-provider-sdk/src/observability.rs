use std::{env, error::Error, io};
use tracing_subscriber::filter::LevelFilter;

const LOG_LEVEL_ENV: &str = "TRAKKIN_LOG";
const DEFAULT_LOG_LEVEL: &str = "info";

pub fn init_provider_tracing(
    provider_id: &'static str,
) -> Result<tracing::Span, Box<dyn Error + Send + Sync>> {
    let level = env::var(LOG_LEVEL_ENV).unwrap_or_else(|_| DEFAULT_LOG_LEVEL.to_owned());
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(true)
        .with_max_level(level.parse::<LevelFilter>()?)
        .with_writer(io::stderr)
        .try_init()?;
    Ok(tracing::info_span!(
        "provider.process",
        provider.id = provider_id,
        process.instance_id = tracing::field::Empty,
    ))
}
