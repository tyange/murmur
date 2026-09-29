//! 신원 키, 기기 키, 기기 위임 인증서(DeviceCert).

use ciborium::Value;
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};

const CERT_DOMAIN: &str = "murmur-cert-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCert {
    pub identity: VerifyingKey,
    pub device: VerifyingKey,
    pub label: String,
    pub issued_at: u64,
    pub sig: Signature,
}

impl DeviceCert {
    pub fn issue(identity: &SigningKey, device: VerifyingKey, label: &str, issued_at: u64) -> Self {
        let identity_pk = identity.verifying_key();
        let msg = cert_message(&identity_pk, &device, label, issued_at);
        let sig = identity.sign(&msg);
        Self {
            identity: identity_pk,
            device,
            label: label.to_owned(),
            issued_at,
            sig,
        }
    }

    pub fn verify(&self) -> Result<(), SignatureError> {
        let msg = cert_message(&self.identity, &self.device, &self.label, self.issued_at);
        self.identity.verify_strict(&msg, &self.sig)
    }
}

pub fn generate_key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS 난수 생성기를 쓸 수 없음");
    SigningKey::from_bytes(&seed)
}

fn cert_message(
    identity: &VerifyingKey,
    device: &VerifyingKey,
    label: &str,
    issued_at: u64,
) -> Vec<u8> {
    let value = Value::Array(vec![
        Value::from(CERT_DOMAIN),
        Value::from(identity.as_bytes().as_slice()),
        Value::from(device.as_bytes().as_slice()),
        Value::from(label),
        Value::from(issued_at),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&value, &mut buf).expect("Vec에 쓰기는 실패하지 않음");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cert() -> DeviceCert {
        let identity = generate_key();
        let device = generate_key();
        DeviceCert::issue(&identity, device.verifying_key(), "laptop", 1_000)
    }

    #[test]
    fn issued_cert_verifies() {
        assert!(sample_cert().verify().is_ok());
    }

    #[test]
    fn tampered_label_is_rejected() {
        let mut cert = sample_cert();
        cert.label = "evil".into();
        assert!(cert.verify().is_err());
    }

    #[test]
    fn swapped_identity_is_rejected() {
        let mut cert = sample_cert();
        cert.identity = generate_key().verifying_key();
        assert!(cert.verify().is_err());
    }

    #[test]
    fn swapped_device_is_rejected() {
        let mut cert = sample_cert();
        cert.device = generate_key().verifying_key();
        assert!(cert.verify().is_err());
    }

    #[test]
    fn cert_message_starts_with_domain() {
        let cert = sample_cert();
        let msg = cert_message(&cert.identity, &cert.device, &cert.label, cert.issued_at);
        assert_eq!(msg[0], 0x85);
        assert_eq!(msg[1], 0x6E);
        assert_eq!(&msg[2..16], CERT_DOMAIN.as_bytes());
    }
}
