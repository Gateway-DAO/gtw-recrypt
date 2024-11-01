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
