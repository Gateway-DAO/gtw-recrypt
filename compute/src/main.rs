use std::net::SocketAddr;

use tonic::transport::Server;

use recrypt_compute::grpc::{
    proto::{self, recrypt_operator_server::RecryptOperatorServer},
    recrypt_operator::Operator,
};

#[tokio::main]
#[allow(dead_code)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:50051".parse::<SocketAddr>()?;
    let service = Operator::default();

    // let reflection_builder = ReflectionBuilder;
    let reflection_svc = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::_FILE_DESCRIPTOR_SET)
        .build_v1()
        .unwrap();

    let server = Server::builder()
        .add_service(reflection_svc)
        .add_service(RecryptOperatorServer::new(service));
    // let bound_server = server
    println!("🚀 gRPC server listening on port: {}", addr.port());

    server.serve(addr).await?;
    Ok(())
}
