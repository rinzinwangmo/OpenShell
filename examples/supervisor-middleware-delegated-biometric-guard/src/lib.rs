// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Delegated biometric guard: an OpenShell supervisor middleware that lets
//! biometric data leave a sandbox only under a signed delegation grant naming
//! the human principal, the purpose, the destination, and the sandbox.

pub mod config;
pub mod detect;
pub mod grant;
pub mod guard;

use std::net::SocketAddr;

use openshell_core::middleware::WebSocketResponseStream;
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    HttpRequestEvaluation, HttpRequestResult, MiddlewareBinding, MiddlewareDescribeRequest,
    MiddlewareManifest, SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
    ValidateConfigRequest, ValidateConfigResponse, WebSocketSessionEvent,
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::config::GuardConfig;
use crate::guard::RequestView;

pub const MANIFEST_NAME: &str = "example/delegated-biometric-guard";
pub const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024;
const PHASE: SupervisorMiddlewarePhase = SupervisorMiddlewarePhase::PreCredentials;

#[derive(Debug, Default, Clone)]
pub struct DelegatedBiometricGuard;

#[tonic::async_trait]
impl SupervisorMiddleware for DelegatedBiometricGuard {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;

    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        let manifest = MiddlewareManifest {
            name: MANIFEST_NAME.into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            // HTTP request bodies only. WebSocket and response inspection are
            // not advertised, so OpenShell never routes them here.
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: PHASE as i32,
                max_payload_bytes: MAX_PAYLOAD_BYTES,
                request_timeout: None,
            }],
            expected_audience: String::new(),
            extension: Some(openshell_core::extension_protocol::extension_metadata(
                openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                MANIFEST_NAME,
                openshell_core::VERSION,
                [],
            )),
        };
        openshell_core::extension_protocol::validate_gateway_metadata(
            openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
            MANIFEST_NAME,
            manifest.extension.as_ref(),
            request.into_inner().gateway,
        )
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
        Ok(Response::new(manifest))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let request = request.into_inner();
        Ok(Response::new(
            match GuardConfig::parse(request.config.as_ref()) {
                Ok(_) => ValidateConfigResponse {
                    valid: true,
                    reason: String::new(),
                },
                Err(reason) => ValidateConfigResponse {
                    valid: false,
                    reason,
                },
            },
        ))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        let request = request.into_inner();
        if request.phase != PHASE as i32 {
            return Err(Status::invalid_argument(format!(
                "unsupported phase '{}'",
                request.phase
            )));
        }
        let config =
            GuardConfig::parse(request.config.as_ref()).map_err(Status::invalid_argument)?;
        let context = request
            .context
            .ok_or_else(|| Status::invalid_argument("request context is required"))?;
        if context.sandbox_id.is_empty() {
            return Err(Status::invalid_argument(
                "request context has no sandbox id",
            ));
        }
        let target = request
            .target
            .ok_or_else(|| Status::invalid_argument("request target is required"))?;
        let headers: Vec<(String, String)> = request
            .headers
            .into_iter()
            .map(|header| (header.name, header.value))
            .collect();
        Ok(Response::new(guard::evaluate(
            &config,
            &RequestView {
                sandbox_id: &context.sandbox_id,
                host: &target.host,
                headers: &headers,
                body: &request.body,
            },
        )))
    }

    async fn evaluate_web_socket_session(
        &self,
        _request: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Err(Status::unimplemented(
            "delegated biometric guard inspects HTTP request bodies only",
        ))
    }
}

/// gRPC server for the guard with message limits sized for the advertised
/// payload plus the contract's envelope.
#[must_use]
pub fn server() -> SupervisorMiddlewareServer<DelegatedBiometricGuard> {
    let limit = MAX_PAYLOAD_BYTES as usize + 512 * 1024;
    SupervisorMiddlewareServer::new(DelegatedBiometricGuard)
        .max_decoding_message_size(limit)
        .max_encoding_message_size(limit)
}

/// Serve on an already-bound listener (used by the demo and tests).
pub async fn serve(listener: tokio::net::TcpListener) -> Result<(), tonic::transport::Error> {
    Server::builder()
        .add_service(server())
        .serve_with_incoming(TcpListenerStream::new(listener))
        .await
}

/// Serve on an address.
pub async fn serve_addr(addr: SocketAddr) -> Result<(), tonic::transport::Error> {
    Server::builder().add_service(server()).serve(addr).await
}
