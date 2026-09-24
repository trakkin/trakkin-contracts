use std::{
    future::Future,
    io::{self, BufRead, Write},
    net::{IpAddr, SocketAddr},
};

use crate::{
    current_protocol_version,
    v1::{
        ProtocolRange,
        adapter_service_server::{AdapterService, AdapterServiceServer},
    },
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{
    Request, Status,
    metadata::{AsciiMetadataValue, MetadataValue},
    service::Interceptor,
    transport::Server,
};

pub const BOOTSTRAP_VERSION: u32 = 1;
pub const LAUNCH_TOKEN_HEADER: &str = "x-trakkin-launch-token";
const ADAPTER_SERVICE_PATH_PREFIX: &str = "/trakkin.adapter.v1.AdapterService/";
pub use crate::bootstrap_v1::{LaunchRequest, ReadyMessage};

impl LaunchRequest {
    pub fn validate(&self) -> Result<SocketAddr, LaunchMessageError> {
        if self.bootstrap_version != BOOTSTRAP_VERSION {
            return Err(LaunchMessageError::UnsupportedVersion(
                self.bootstrap_version,
            ));
        }
        if self.process_instance_id.is_empty() {
            return Err(LaunchMessageError::MissingProcessInstanceId);
        }
        if self.launch_token.is_empty() {
            return Err(LaunchMessageError::MissingLaunchToken);
        }
        let address = self
            .bind_address
            .parse::<SocketAddr>()
            .map_err(LaunchMessageError::InvalidBindAddress)?;
        if !is_loopback(address.ip()) {
            return Err(LaunchMessageError::NonLoopbackAddress);
        }
        Ok(address)
    }
}

pub fn read_launch_request(mut reader: impl BufRead) -> Result<LaunchRequest, LaunchMessageError> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(LaunchMessageError::MissingMessage);
    }
    let launch = serde_json::from_str::<LaunchRequest>(&line)?;
    launch.validate()?;
    Ok(launch)
}

pub fn write_ready_message(
    mut writer: impl Write,
    message: &ReadyMessage,
) -> Result<(), LaunchMessageError> {
    if message.bootstrap_version != BOOTSTRAP_VERSION {
        return Err(LaunchMessageError::UnsupportedVersion(
            message.bootstrap_version,
        ));
    }
    if message.process_instance_id.is_empty() {
        return Err(LaunchMessageError::MissingProcessInstanceId);
    }
    if message.launch_token.is_empty() {
        return Err(LaunchMessageError::MissingLaunchToken);
    }
    let address = message
        .address
        .parse::<SocketAddr>()
        .map_err(LaunchMessageError::InvalidBindAddress)?;
    if !is_loopback(address.ip()) {
        return Err(LaunchMessageError::NonLoopbackAddress);
    }
    serde_json::to_writer(&mut writer, message)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum LaunchMessageError {
    #[error("adapter bootstrap I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("invalid adapter bootstrap JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("adapter bootstrap message is missing")]
    MissingMessage,
    #[error("unsupported adapter bootstrap version {0}")]
    UnsupportedVersion(u32),
    #[error("adapter process instance ID is missing")]
    MissingProcessInstanceId,
    #[error("adapter launch token is missing")]
    MissingLaunchToken,
    #[error("adapter bind address is invalid: {0}")]
    InvalidBindAddress(std::net::AddrParseError),
    #[error("adapter bind address must be loopback")]
    NonLoopbackAddress,
}

#[derive(Clone, Debug)]
pub struct LaunchToken(AsciiMetadataValue);

impl LaunchToken {
    pub fn new(value: &str) -> Result<Self, InvalidLaunchToken> {
        if value.is_empty() {
            return Err(InvalidLaunchToken);
        }
        let mut value = MetadataValue::try_from(value).map_err(|_| InvalidLaunchToken)?;
        value.set_sensitive(true);
        Ok(Self(value))
    }

    pub fn apply<T>(&self, request: &mut Request<T>) {
        request
            .metadata_mut()
            .insert(LAUNCH_TOKEN_HEADER, self.0.clone());
    }

    pub fn interceptor(&self) -> LaunchTokenInterceptor {
        LaunchTokenInterceptor {
            expected: self.0.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LaunchTokenInterceptor {
    expected: AsciiMetadataValue,
}

impl Interceptor for LaunchTokenInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        if request
            .metadata()
            .get(LAUNCH_TOKEN_HEADER)
            .is_some_and(|actual| actual == self.expected)
        {
            Ok(request)
        } else {
            Err(Status::unauthenticated("invalid launch token"))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("launch token must be non-empty ASCII metadata")]
pub struct InvalidLaunchToken;

pub fn supported_protocol_range() -> ProtocolRange {
    let current = current_protocol_version();
    ProtocolRange {
        minimum: Some(current),
        maximum: Some(current),
    }
}

fn rpc_method(path: &str) -> &str {
    path.strip_prefix(ADAPTER_SERVICE_PATH_PREFIX)
        .filter(|method| !method.is_empty() && !method.contains('/'))
        .unwrap_or("Unknown")
}

pub async fn serve_adapter<T, F, W>(
    launch: &LaunchRequest,
    adapter: T,
    mut ready_writer: W,
    shutdown: F,
) -> Result<(), ServeError>
where
    T: AdapterService,
    F: Future<Output = ()>,
    W: Write,
{
    let bind_address = launch.validate()?;
    let token = LaunchToken::new(&launch.launch_token)?;
    let listener = TcpListener::bind(bind_address).await?;
    let address = listener.local_addr()?;
    let ready = ReadyMessage {
        bootstrap_version: BOOTSTRAP_VERSION,
        process_instance_id: launch.process_instance_id.clone(),
        address: address.to_string(),
        launch_token: launch.launch_token.clone(),
    };
    write_ready_message(&mut ready_writer, &ready)?;
    drop(ready_writer);

    Server::builder()
        .trace_fn(|request| {
            tracing::info_span!(
                "provider.rpc",
                rpc.system = "grpc",
                rpc.service = "trakkin.adapter.v1.AdapterService",
                rpc.method = rpc_method(request.uri().path())
            )
        })
        .add_service(AdapterServiceServer::with_interceptor(
            adapter,
            token.interceptor(),
        ))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await?;

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error(transparent)]
    Launch(#[from] LaunchMessageError),
    #[error(transparent)]
    Token(#[from] InvalidLaunchToken),
    #[error("adapter listener failed: {0}")]
    Io(#[from] io::Error),
    #[error("adapter gRPC server failed: {0}")]
    Transport(#[from] tonic::transport::Error),
}

fn is_loopback(address: IpAddr) -> bool {
    address.is_loopback()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use tonic::{Code, Request, service::Interceptor};

    use super::{
        ADAPTER_SERVICE_PATH_PREFIX, BOOTSTRAP_VERSION, LAUNCH_TOKEN_HEADER, LaunchRequest,
        LaunchToken, ReadyMessage, read_launch_request, rpc_method, supported_protocol_range,
        write_ready_message,
    };

    fn launch() -> LaunchRequest {
        LaunchRequest {
            bootstrap_version: BOOTSTRAP_VERSION,
            process_instance_id: "process-1".to_owned(),
            bind_address: "127.0.0.1:0".to_owned(),
            launch_token: "secret-token".to_owned(),
        }
    }

    #[test]
    fn bootstrap_round_trip_is_versioned_and_loopback_only() {
        let launch = launch();
        let encoded = serde_json::to_string(&launch).unwrap();
        assert_eq!(
            encoded,
            r#"{"bootstrapVersion":1,"processInstanceId":"process-1","bindAddress":"127.0.0.1:0","launchToken":"secret-token"}"#
        );
        let encoded = format!("{encoded}\n");
        assert_eq!(read_launch_request(Cursor::new(encoded)).unwrap(), launch);

        let ready = ReadyMessage {
            bootstrap_version: BOOTSTRAP_VERSION,
            process_instance_id: "process-1".to_owned(),
            address: "127.0.0.1:1234".to_owned(),
            launch_token: "secret-token".to_owned(),
        };
        let mut output = Vec::new();
        write_ready_message(&mut output, &ready).unwrap();
        assert_eq!(
            serde_json::from_slice::<ReadyMessage>(&output).unwrap(),
            ready
        );

        let mut invalid = launch;
        invalid.bind_address = "0.0.0.0:0".to_owned();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn launch_token_client_and_server_helpers_fail_closed() {
        let token = LaunchToken::new("secret-token").unwrap();
        let mut request = Request::new(());
        token.apply(&mut request);
        assert!(request.metadata().contains_key(LAUNCH_TOKEN_HEADER));
        assert!(token.interceptor().call(request).is_ok());

        let mut interceptor = token.interceptor();
        assert_eq!(
            interceptor.call(Request::new(())).unwrap_err().code(),
            Code::Unauthenticated
        );
    }

    #[test]
    fn sdk_advertises_only_the_current_contract_version() {
        let range = supported_protocol_range();
        assert_eq!(range.minimum, Some(crate::current_protocol_version()));
        assert_eq!(range.maximum, Some(crate::current_protocol_version()));
    }

    #[test]
    fn rpc_method_is_scoped_to_the_adapter_service() {
        assert_eq!(
            rpc_method("/trakkin.adapter.v1.AdapterService/ReadCatalog"),
            "ReadCatalog"
        );
        assert_eq!(
            rpc_method("/trakkin.adapter.v1.AdapterService/FutureMethod"),
            "FutureMethod"
        );
        assert_eq!(rpc_method("/arbitrary/service/secret-value"), "Unknown");
        assert_eq!(
            rpc_method("/trakkin.adapter.v1.AdapterService/Nested/Method"),
            "Unknown"
        );
        assert_eq!(rpc_method(ADAPTER_SERVICE_PATH_PREFIX), "Unknown");
    }
}
