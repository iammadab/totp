extern crate core;

use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

// TODO: move to another file, add documentation
fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha1::new_from_slice(key).unwrap();
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

// TODO: use types to restrict this to exactly 20 bytes
fn truncate(bytes: &[u8]) -> u32 {
    let last_byte = bytes[19];
    let offset = (last_byte & 0xf) as usize;
    // TODO: can't I do this with a vector??
    let offset_byte = (((bytes[offset] & 0x7f) as u32) << 24)
        | ((bytes[offset + 1] as u32) << 16)
        | ((bytes[offset + 2] as u32) << 8)
        | (bytes[offset + 3] as u32);
    // TODO: make this const
    offset_byte % 1000_000
}

#[cfg(test)]
mod test {
    use crate::{hmac_sha1, truncate};

    #[test]
    fn test_hmac_sha1() {
        let result = hmac_sha1(b"secret", b"message1");
        assert_eq!(
            hex::encode(result),
            "31d729cfa51d33d8afa6793736b4dbc17dc5bd81"
        );
    }

    #[test]
    fn test_truncation() {
        let hmac_sha1_digest = hex::decode("1f8698690e02ca16618550ef7f19da8e945b555a").unwrap();
        assert_eq!(truncate(&hmac_sha1_digest), 872921);
    }
}
