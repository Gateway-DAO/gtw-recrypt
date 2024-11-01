use base64::Engine;
use recrypt::{
    api::Hashable,
    api_480::{EncryptedValue, PrivateKey},
};
use tonic::{Request, Response, Status};

#[allow(unused_macros)]
macro_rules! encode_base64 {
    ($data:expr) => {
        base64::engine::general_purpose::STANDARD.encode($data)
    };
}

#[allow(unused_macros)]
macro_rules! decode_base64 {
    ($data:expr) => {
        base64::engine::general_purpose::STANDARD.decode($data)
    };
}

use proto::{
    rencrypt_operator_server::RencryptOperator, DecryptRequest, DecryptedReply,
    GenerateKeyPairRequest, KeyPairReply, RencryptReply, RencryptRequest,
};
pub mod proto {
    tonic::include_proto!("rencrypt");
    pub const _FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("rencryptservice_descriptor");
}

#[derive(Default, Debug)]
pub struct Operator {}

#[tonic::async_trait]
impl RencryptOperator for Operator {
    async fn generate_key_pair(
        &self,
        _req: Request<GenerateKeyPairRequest>,
    ) -> Result<Response<KeyPairReply>, Status> {
        let (privkey, pubkey) = crate::crypto::encryption::recrypt::new_encryption_keypair();

        let reply = KeyPairReply {
            pubkey_base64: base64::engine::general_purpose::STANDARD.encode(pubkey.to_bytes()),
            privkey_base64: base64::engine::general_purpose::STANDARD.encode(privkey.to_bytes()),
        };

        Ok(Response::new(reply))
    }

    async fn rencrypt(
        &self,
        req: Request<RencryptRequest>,
    ) -> Result<Response<RencryptReply>, Status> {
        let req_params = req.into_inner();

        let encrypted_value_encoding = req_params.cipher_base64;

        let encrypted_value_buffer = base64::engine::general_purpose::STANDARD
            .decode(encrypted_value_encoding)
            .unwrap();
        let encrypted_value = EncryptedValue::from_bytes(encrypted_value_buffer).unwrap();

        let transform_key_encoding = req_params.transformkey_base64;
        let transform_key_buffer =
            match base64::engine::general_purpose::STANDARD.decode(transform_key_encoding) {
                Ok(key) => key,
                Err(err) => return Err(Status::from_error(Box::new(err))),
            };
        let transform_key = recrypt::api_480::TransformKey::from_bytes(&transform_key_buffer);

        let signing_keys = crate::crypto::signature::ed25519::new_signing_keypair();

        let transformed_data = crate::crypto::encryption::recrypt::transform(
            encrypted_value,
            transform_key,
            &signing_keys,
        );

        Ok(Response::new(RencryptReply {
            transformed_base64: base64::engine::general_purpose::STANDARD
                .encode(transformed_data.as_bytes()),
        }))
    }

    async fn decrypt(
        &self,
        req: Request<DecryptRequest>,
    ) -> Result<Response<DecryptedReply>, Status> {
        let req_params = req.into_inner();

        let encryption_buffer = base64::engine::general_purpose::STANDARD
            .decode(req_params.cipher_base64)
            .unwrap();
        let encryption = EncryptedValue::from_bytes(encryption_buffer).unwrap();

        let privkey = PrivateKey::new_from_slice(
            base64::engine::general_purpose::STANDARD
                .decode(req_params.privkey_base64)
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        Ok(Response::new(DecryptedReply {
            payload: String::from_utf8(
                crate::crypto::encryption::recrypt::decrypt(
                    &encryption,
                    &privkey,
                    req_params.decryption_length as usize,
                )
                .unwrap(),
            )
            .unwrap(),
        }))
    }
}

#[cfg(test)]
mod test {
    use base64::Engine;
    use recrypt::api_480::{EncryptedValue, PrivateKey, TransformKey};

    #[test]
    fn generate_test_transform_key() {
        let (privkey, pubkey) = crate::crypto::encryption::recrypt::new_encryption_keypair();
        let signing_keypair = crate::crypto::signature::ed25519::new_signing_keypair();

        let data = "something random";
        let encryption =
            crate::crypto::encryption::recrypt::encrypt(data.as_bytes(), &pubkey, &signing_keypair)
                .unwrap();

        let (privkey2, pubkey2) = crate::crypto::encryption::recrypt::new_encryption_keypair();

        let transformkey = crate::crypto::encryption::recrypt::new_transform_key(
            &privkey,
            &pubkey2,
            &signing_keypair,
        );

        let transformkey_encoded = transformkey.to_bytes();
        let transformkey_decoded = TransformKey::from_bytes(&transformkey_encoded);

        use crate::crypto::encryption::recrypt::transform;
        let transformed_data =
            transform(encryption.clone(), transformkey_decoded, &signing_keypair);

        let unencryption =
            crate::crypto::encryption::recrypt::decrypt(&transformed_data, &privkey2, data.len())
                .unwrap();

        assert_eq!(String::from_utf8(unencryption).unwrap(), data);

        // print grpc-relevant data
        println!("===data length===\n{}", data.len());
        println!();
        println!(
            "===encryption===\n{}",
            encode_base64!(encryption.as_bytes())
        );
        println!();
        println!(
            "===transformation key===\n{}",
            encode_base64!(transformkey_encoded)
        );
        println!();
        println!("===decryption key===\n{}", encode_base64!(privkey2.bytes()));
        println!();

        // attempt to reconstruct data from encodings
        let reconstruct_privkey = PrivateKey::new_from_slice(privkey2.bytes()).unwrap();
        let reconstruct_transformed =
            EncryptedValue::from_bytes(transformed_data.as_bytes()).unwrap();

        let decryption = crate::crypto::encryption::recrypt::decrypt(
            &reconstruct_transformed,
            &reconstruct_privkey,
            data.len(),
        )
        .unwrap();
        assert_eq!(String::from_utf8(decryption).unwrap(), data);
    }
}
