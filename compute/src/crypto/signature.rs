
pub mod ed25519 {
    use recrypt::{
        api::SigningKeypair as Ed25519Keypair,
        api_480::{Ed25519Ops, Recrypt480},
    };

    pub fn new_signing_keypair() -> Ed25519Keypair {
        let recrypt = Recrypt480::new();
        recrypt.generate_ed25519_key_pair()
    }
}
