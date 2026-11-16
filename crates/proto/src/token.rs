//! Ballot tokens: RSA blind signatures (RFC 9474, RSABSSA-SHA384-PSS-
//! Randomized), as in anonymous voting.
//!
//! Options::default() with randomized messages is RFC 9474's
//! RSABSSA-SHA384-PSS-Randomized.
//!
//! An enrolled participant asks the server to sign a batch of blinded
//! random nonces. The server checks the enrollment code and signs, but sees
//! only the blinded values. The app unblinds them and spends one token per
//! ballot. The server can check a token is valid and unspent, but cannot
//! tell which participant it was issued to. Each epoch has its own key, so
//! a token is only good for the epoch it was issued for.
//!
//! The app fetches the epoch's public key anonymously (through the relay)
//! before asking for signatures, and `finalize` checks every signature
//! against it. A server that signed one participant's tokens with a
//! dedicated key, to recognise them later, would be detected.

use anyhow::{anyhow, bail, Context, Result};
use blind_rsa_signatures::{BlindSignature, KeyPair, MessageRandomizer, Options, PublicKey, Secret, SecretKey, Signature};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

pub const NONCE_LEN: usize = 32;
pub const KEY_BITS: usize = 2048;

/// What is signed: a domain tag, the epoch and the random nonce.
fn message(epoch: u32, nonce: &[u8]) -> Vec<u8> {
    let mut m = b"peersig/v1/ballot".to_vec();
    m.extend_from_slice(&epoch.to_be_bytes());
    m.extend_from_slice(nonce);
    m
}

/// A spendable token.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub epoch: u32,
    #[serde(with = "crate::b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::b64")]
    pub randomizer: Vec<u8>,
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

/// Client side: a blinded nonce waiting for its signature.
#[derive(Serialize, Deserialize, Clone)]
pub struct Blinded {
    pub epoch: u32,
    #[serde(with = "crate::b64")]
    nonce: Vec<u8>,
    #[serde(with = "crate::b64")]
    secret: Vec<u8>,
    #[serde(with = "crate::b64")]
    randomizer: Vec<u8>,
    /// What the server signs.
    #[serde(with = "crate::b64")]
    pub blind_message: Vec<u8>,
}

/// Short id of a public key, shown to participants and compared across
/// fetches.
pub fn key_id(pk_der: &[u8]) -> String {
    crate::short_hash(pk_der, 8)
}

fn public_key(pk_der: &[u8]) -> Result<PublicKey> {
    PublicKey::from_der(pk_der).map_err(|e| anyhow!("token key: {}", e))
}

/// Blinds `n` fresh random nonces for `epoch`.
pub fn blind(pk_der: &[u8], epoch: u32, n: usize) -> Result<Vec<Blinded>> {
    let pk = public_key(pk_der)?;
    (0..n)
        .map(|_| {
            let mut nonce = vec![0u8; NONCE_LEN];
            rand::fill(&mut nonce[..]);
            let r = pk.blind(&mut OsRng, message(epoch, &nonce), true, &Options::default()).map_err(|e| anyhow!("blind: {}", e))?;
            Ok(Blinded {
                epoch,
                nonce,
                secret: r.secret.0,
                randomizer: r.msg_randomizer.map(|m| m.0.to_vec()).unwrap_or_default(),
                blind_message: r.blind_msg.0,
            })
        })
        .collect()
}

/// Unblinds the server's signatures; fails if any does not verify under
/// `pk_der`.
pub fn finalize(pk_der: &[u8], blinded: &[Blinded], signatures: &[Vec<u8>]) -> Result<Vec<Token>> {
    if blinded.len() != signatures.len() {
        bail!("{} signatures for {} tokens", signatures.len(), blinded.len());
    }
    let pk = public_key(pk_der)?;
    blinded
        .iter()
        .zip(signatures)
        .map(|(b, s)| {
            let randomizer: [u8; 32] = b.randomizer.as_slice().try_into().context("randomizer")?;
            let sig = pk
                .finalize(
                    &BlindSignature(s.clone()),
                    &Secret(b.secret.clone()),
                    Some(MessageRandomizer(randomizer)),
                    message(b.epoch, &b.nonce),
                    &Options::default(),
                )
                .map_err(|e| anyhow!("signature does not verify under the published key: {}", e))?;
            Ok(Token { epoch: b.epoch, nonce: b.nonce.clone(), randomizer: b.randomizer.clone(), signature: sig.0 })
        })
        .collect()
}

/// Server side.
pub struct Issuer {
    sk: SecretKey,
    pk: PublicKey,
    pk_der: Vec<u8>,
}

impl Issuer {
    pub fn generate() -> Result<Self> {
        let kp = KeyPair::generate(&mut OsRng, KEY_BITS).map_err(|e| anyhow!("keygen: {}", e))?;
        Self::from_parts(kp.sk, kp.pk)
    }

    pub fn from_der(sk_der: &[u8]) -> Result<Self> {
        let sk = SecretKey::from_der(sk_der).map_err(|e| anyhow!("token secret key: {}", e))?;
        let pk = sk.public_key().map_err(|e| anyhow!("{}", e))?;
        Self::from_parts(sk, pk)
    }

    fn from_parts(sk: SecretKey, pk: PublicKey) -> Result<Self> {
        let pk_der = pk.to_der().map_err(|e| anyhow!("{}", e))?;
        Ok(Issuer { sk, pk, pk_der })
    }

    pub fn secret_der(&self) -> Result<Vec<u8>> {
        self.sk.to_der().map_err(|e| anyhow!("{}", e))
    }

    pub fn public_der(&self) -> &[u8] {
        &self.pk_der
    }

    pub fn sign(&self, blind_message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.sk.blind_sign(&mut OsRng, blind_message, &Options::default()).map_err(|e| anyhow!("blind sign: {}", e))?.0)
    }

    pub fn verify(&self, t: &Token) -> bool {
        let Ok(randomizer) = <[u8; 32]>::try_from(t.randomizer.as_slice()) else { return false };
        t.nonce.len() == NONCE_LEN
            && Signature(t.signature.clone())
                .verify(&self.pk, Some(MessageRandomizer(randomizer)), message(t.epoch, &t.nonce), &Options::default())
                .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_spend() {
        let issuer = Issuer::generate().unwrap();
        let issuer = Issuer::from_der(&issuer.secret_der().unwrap()).unwrap();
        let pk = issuer.public_der().to_vec();
        let blinded = blind(&pk, 7, 3).unwrap();
        let sigs: Vec<Vec<u8>> = blinded.iter().map(|b| issuer.sign(&b.blind_message).unwrap()).collect();
        let tokens = finalize(&pk, &blinded, &sigs).unwrap();
        assert_eq!(tokens.len(), 3);
        for t in &tokens {
            assert!(issuer.verify(t));
            // What the server signed is not what it later sees.
            assert!(blinded.iter().all(|b| b.blind_message != t.signature && !b.blind_message.windows(NONCE_LEN).any(|w| w == t.nonce)));
        }
        // A token is bound to its epoch.
        let mut wrong = tokens[0].clone();
        wrong.epoch = 8;
        assert!(!issuer.verify(&wrong));
    }

    #[test]
    fn other_key_is_detected() {
        let published = Issuer::generate().unwrap();
        let tagging = Issuer::generate().unwrap();
        // A blinded value can exceed the other key's modulus, and then it
        // cannot even sign it: try until it can, and check the app refuses.
        let mut checked = 0;
        for _ in 0..20 {
            let blinded = blind(published.public_der(), 1, 1).unwrap();
            if let Ok(sig) = tagging.sign(&blinded[0].blind_message) {
                assert!(finalize(published.public_der(), &blinded, &[sig]).is_err());
                checked += 1;
            }
        }
        assert!(checked > 0);
    }
}
