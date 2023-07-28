use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha1::new_from_slice(key).unwrap();
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod test {
    use crate::hmac_sha1;

    #[test]
    fn test_hmac_sha1() {
        let result = hmac_sha1(b"secret", b"message1");
        assert_eq!(
            hex::encode(result),
            "31d729cfa51d33d8afa6793736b4dbc17dc5bd81"
        );
    }
}
