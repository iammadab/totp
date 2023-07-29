use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

struct TOTP<'a> {
    secret: &'a [u8],
    modulo: u32,
    time_step: u64,
}

impl<'a> TOTP<'a> {
    /// Initialize TOTP struct
    fn new(secret: &'a [u8], modulo: u32, time_step: u64) -> Self {
        Self {
            secret,
            modulo,
            time_step,
        }
    }

    /// Returns the code at the current time
    fn code(&self) -> u32 {
        let now = SystemTime::now();
        let since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
        let time_step_count = since_epoch.as_secs() / 30;
        self.totp(time_step_count)
    }

    /// Returns the code for the supplied time in seconds since UNIX_EPOCH
    fn code_at(&self, seconds: u64) -> u32 {
        let time_step_count = seconds / 30;
        self.totp(time_step_count)
    }

    /// TOTP = HOTP(K, T)
    /// where K is the secret and T is the time_step_count
    fn totp(&self, time_step_count: u64) -> u32 {
        self.hotp(&time_step_count.to_be_bytes())
    }

    /// HOTP = truncate(hmac_sha1(K, C))
    /// where K is the secret and C is some seed value
    fn hotp(&self, seed: &[u8]) -> u32 {
        truncate(&hmac_sha1(self.secret, seed), self.modulo)
    }
}

/// Computes hmac using sha1 as the underlying hashing algorithm
fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha1::new_from_slice(key).unwrap();
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Converts hmac bytes to n digit number (determined by modulo length)
fn truncate(bytes: &[u8], modulo: u32) -> u32 {
    let last_byte = bytes[19];
    let offset = (last_byte & 0xf) as usize;
    let offset_byte = (((bytes[offset] & 0x7f) as u32) << 24)
        | ((bytes[offset + 1] as u32) << 16)
        | ((bytes[offset + 2] as u32) << 8)
        | (bytes[offset + 3] as u32);
    offset_byte % modulo
}

#[cfg(test)]
mod test {
    use crate::{hmac_sha1, truncate, TOTP};

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
        assert_eq!(truncate(&hmac_sha1_digest, 1000_000), 872921);
    }

    #[test]
    fn test_totp() {
        let totp = TOTP::new(b"12345678901234567890", 10000_0000, 30);
        assert_eq!(totp.code_at(59), 94287082);
        assert_eq!(totp.code_at(1111111109), 07081804);
        assert_eq!(totp.code_at(1111111111), 14050471);
        assert_eq!(totp.code_at(1234567890), 89005924);
        assert_eq!(totp.code_at(2000000000), 69279037);
        assert_eq!(totp.code_at(20000000000), 65353130);
    }
}
