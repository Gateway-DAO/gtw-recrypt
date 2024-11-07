use crate::crypto::encryption::recrypt::{
    decrypt, encrypt, new_transform_key, pubkey_from_buffer, transform,
};
use crate::crypto::signature::ed25519::*;
use base64::Engine;
use proto::recrypt_operator_server::RecryptOperator;
use proto::GenerateTransformKeyRequest;
use proto::{
    DecryptRequest, Empty, EncodedKeyPair, EncodedPayload, EncryptReply, EncryptRequest,
    TransformRequest,
};
use recrypt::api::{EncryptedValue, Hashable, PrivateKey, TransformKey};
use tonic::{Request, Response, Status};

pub mod proto {
    tonic::include_proto!("recrypt");
    pub const _FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("recryptservice_descriptor");
}

macro_rules! encode64 {
    ($e:expr) => {
        base64::engine::general_purpose::STANDARD.encode($e)
    };
}

macro_rules! decode64 {
    ($e:expr) => {
        base64::engine::general_purpose::STANDARD.decode($e)
    };
}

#[derive(Default, Debug)]
pub struct Operator {}

static _SIGNING_KEYPAIR: once_cell::sync::Lazy<
    std::sync::Arc<recrypt::internal::ed25519::SigningKeypair>,
> = once_cell::sync::Lazy::new(|| {
    std::sync::Arc::new(crate::crypto::signature::ed25519::new_signing_keypair())
});

#[tonic::async_trait]
impl RecryptOperator for Operator {
    async fn generate_key_pair(
        &self,
        _req: Request<Empty>,
    ) -> Result<Response<EncodedKeyPair>, Status> {
        let (privkey, pubkey) = crate::crypto::encryption::recrypt::new_encryption_keypair();

        let reply = EncodedKeyPair {
            pubkey_base64: encode64!(pubkey.to_bytes()),
            privkey_base64: encode64!(privkey.to_bytes()),
        };

        Ok(Response::new(reply))
    }

    async fn generate_transform_key(
        &self,
        req: Request<GenerateTransformKeyRequest>,
    ) -> Result<Response<EncodedPayload>, Status> {
        let req_params = req.into_inner();

        let from_privkey_serialized = decode64!(req_params.from_privkey_base64).unwrap();
        let from_privkey = PrivateKey::new_from_slice(from_privkey_serialized.as_slice()).unwrap();
        let to_pubkey_serialized = decode64!(req_params.to_pubkey_base64).unwrap();
        let to_pubkey = pubkey_from_buffer(to_pubkey_serialized).unwrap();

        let transform_key = new_transform_key(&from_privkey, &to_pubkey, &_SIGNING_KEYPAIR);

        Ok(Response::new(EncodedPayload {
            payload_base64: base64::engine::general_purpose::STANDARD
                .encode(transform_key.to_bytes()),
        }))
    }

    async fn transform(
        &self,
        req: Request<TransformRequest>,
    ) -> Result<Response<EncodedPayload>, Status> {
        let req_params = req.into_inner();

        let encryption_encoding = decode64!(req_params.cipher_base64).unwrap();
        let encryption = EncryptedValue::from_bytes(encryption_encoding).unwrap();

        let transformkey_encoded = decode64!(req_params.transformkey_base64).unwrap();
        let transformkey_decoded = TransformKey::from_bytes(&transformkey_encoded);

        let signing_keypair = new_signing_keypair();
        let transformed_data =
            transform(encryption.clone(), transformkey_decoded, &signing_keypair);

        Ok(Response::new(EncodedPayload {
            payload_base64: base64::engine::general_purpose::STANDARD
                .encode(transformed_data.as_bytes()),
        }))
    }

    async fn decrypt(
        &self,
        req: Request<DecryptRequest>,
    ) -> Result<Response<EncodedPayload>, Status> {
        let req_params = req.into_inner();

        // deserialize private key
        let privkey_encoding = req_params.privkey_base64;
        let privkey_serialized = base64::engine::general_purpose::STANDARD
            .decode(privkey_encoding)
            .unwrap();
        let privkey = PrivateKey::new_from_slice(privkey_serialized.as_slice()).unwrap();

        // deserialize encrypted value
        let cipher_encoding = req_params.cipher_base64;
        let cipher_serialized = base64::engine::general_purpose::STANDARD
            .decode(cipher_encoding)
            .unwrap();
        let cipher = EncryptedValue::from_bytes(cipher_serialized).unwrap();

        let data_len = req_params.length;

        let decryption = decrypt(&cipher, &privkey, data_len as usize).unwrap();
        Ok(Response::new(EncodedPayload {
            payload_base64: encode64!(decryption),
        }))
    }

    async fn encrypt(
        &self,
        _req: Request<EncryptRequest>,
    ) -> Result<Response<EncryptReply>, Status> {
        let req = _req.into_inner();

        let pubkey = base64::engine::general_purpose::STANDARD
            .decode(req.pubkey_base64)
            .unwrap();
        let pubkey = pubkey_from_buffer(pubkey).unwrap();

        let data = req.data.as_str();

        let encryption = encrypt(data.as_bytes(), &pubkey, &_SIGNING_KEYPAIR).unwrap();

        println!("Data length: {}", data.chars().count());

        Ok(Response::new(EncryptReply {
            cipher_base64: encode64!(encryption.as_bytes()),
            length: data.len() as f32,
        }))
    }
}
