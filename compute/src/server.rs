use std::net::SocketAddr;

use recrypt_compute::grpc::rencrypt_operator::{
    proto::{self, rencrypt_operator_server::RencryptOperatorServer},
    Operator,
};
use tonic::transport::Server;

#[tokio::main]
#[allow(dead_code)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:50051".parse::<SocketAddr>()?;
    let service = Operator::default();

    // let reflection_builder = ReflectionBuilder;
    let reflection_svc = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::_FILE_DESCRIPTOR_SET)
        .build_v1()
        .unwrap();

    let server = Server::builder()
        .add_service(reflection_svc)
        .add_service(RencryptOperatorServer::new(service));
    // let bound_server = server
    println!("🚀 gRPC server listening on port: {}", addr.port());

    server.serve(addr).await?;
    Ok(())
}
