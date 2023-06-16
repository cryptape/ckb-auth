use anyhow::{anyhow, Error};

pub(crate) fn decode_string(s: &str, encoding: &str) -> Result<Vec<u8>, Error> {
    match encoding {
        "hex" => Ok(hex::decode(s)?),
        "base64" => {
            use base64::{engine::general_purpose, Engine as _};
            Ok(general_purpose::STANDARD.decode(s)?)
        }
        _ => Err(anyhow!("Unknown encoding {}", encoding)),
    }
}
