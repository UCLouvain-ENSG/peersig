//! Oblivious HTTP (RFC 9458) with Binary HTTP (RFC 9292) inside.
//!
//! The app encrypts each request to the server's gateway key and posts it
//! to a relay run by another party. The relay sees the participant's
//! address and an opaque blob; the server's gateway sees the request but
//! only the relay's address. Without a relay, the app posts to the server's
//! own gateway: same code, no address hiding.

use std::io::Cursor;

use anyhow::{anyhow, Context, Result};
use bhttp::{Message, Mode, StatusCode};
use ohttp::hpke::{Aead, Kdf, Kem};
use ohttp::{KeyConfig, SymmetricSuite};

pub use ohttp::{ClientRequest, ClientResponse, Server, ServerResponse};

pub const KEY_ID: u8 = 1;
pub const REQUEST_TYPE: &str = "message/ohttp-req";
pub const RESPONSE_TYPE: &str = "message/ohttp-res";
pub const KEYS_TYPE: &str = "application/ohttp-keys";

/// Gateway key derived from a stored 32-byte seed, so it survives restarts.
pub fn gateway(seed: &[u8]) -> Result<Server> {
    ohttp::init();
    let config = KeyConfig::derive(
        KEY_ID,
        Kem::X25519Sha256,
        vec![
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
        ],
        seed,
    )
    .map_err(|e| anyhow!("ohttp key: {:?}", e))?;
    Server::new(config).map_err(|e| anyhow!("ohttp gateway: {:?}", e))
}

/// `application/ohttp-keys` body for a gateway.
pub fn key_config(server: &Server) -> Result<Vec<u8>> {
    KeyConfig::encode_list(&[server.config()]).map_err(|e| anyhow!("{:?}", e))
}

pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

pub fn encode_request(method: &str, path: &str, body: &[u8]) -> Result<Vec<u8>> {
    let mut m = Message::request(method.as_bytes().to_vec(), b"https".to_vec(), b"peersig".to_vec(), path.as_bytes().to_vec());
    if !body.is_empty() {
        m.put_header("content-type", "application/json");
        m.write_content(body);
    }
    let mut out = Vec::new();
    m.write_bhttp(Mode::KnownLength, &mut out).map_err(|e| anyhow!("{:?}", e))?;
    Ok(out)
}

pub fn decode_request(bytes: &[u8]) -> Result<Request> {
    let m = Message::read_bhttp::<_, Cursor<&[u8]>>(&mut Cursor::new(bytes)).map_err(|e| anyhow!("bhttp: {:?}", e))?;
    let c = m.control();
    let method = String::from_utf8(c.method().context("not a request")?.to_vec())?;
    let path = String::from_utf8(c.path().context("no path")?.to_vec())?;
    Ok(Request { method, path, body: m.content().to_vec() })
}

pub fn encode_response(status: u16, body: &[u8]) -> Result<Vec<u8>> {
    let mut m = Message::response(StatusCode::try_from(status).map_err(|e| anyhow!("{:?}", e))?);
    m.put_header("content-type", "application/json");
    m.write_content(body);
    let mut out = Vec::new();
    m.write_bhttp(Mode::KnownLength, &mut out).map_err(|e| anyhow!("{:?}", e))?;
    Ok(out)
}

pub fn decode_response(bytes: &[u8]) -> Result<(u16, Vec<u8>)> {
    let m = Message::read_bhttp::<_, Cursor<&[u8]>>(&mut Cursor::new(bytes)).map_err(|e| anyhow!("bhttp: {:?}", e))?;
    let status = m.control().status().context("not a response")?.code();
    Ok((status, m.content().to_vec()))
}

/// Client side: encrypts a request for the gateway whose key list is
/// `keys`.
pub fn encapsulate(keys: &[u8], method: &str, path: &str, body: &[u8]) -> Result<(Vec<u8>, ClientResponse)> {
    ohttp::init();
    let req = ClientRequest::from_encoded_config_list(keys).map_err(|e| anyhow!("ohttp keys: {:?}", e))?;
    req.encapsulate(&encode_request(method, path, body)?).map_err(|e| anyhow!("{:?}", e))
}

pub fn decapsulate_response(resp: ClientResponse, enc: &[u8]) -> Result<(u16, Vec<u8>)> {
    decode_response(&resp.decapsulate(enc).map_err(|e| anyhow!("ohttp response: {:?}", e))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let gw = gateway(&[7u8; 32]).unwrap();
        let keys = key_config(&gw).unwrap();
        // Same seed, same key: restarts keep the published key.
        assert_eq!(keys, key_config(&gateway(&[7u8; 32]).unwrap()).unwrap());
        let (enc, client) = encapsulate(&keys, "POST", "/v1/ballot", br#"{"x":1}"#).unwrap();
        assert!(!enc.windows(9).any(|w| w == b"v1/ballot"), "path visible to the relay");
        let (plain, server) = gw.decapsulate(&enc).unwrap();
        let req = decode_request(&plain).unwrap();
        assert_eq!((req.method.as_str(), req.path.as_str(), req.body.as_slice()), ("POST", "/v1/ballot", &br#"{"x":1}"#[..]));
        let enc_res = server.encapsulate(&encode_response(204, b"").unwrap()).unwrap();
        assert_eq!(decapsulate_response(client, &enc_res).unwrap(), (204, vec![]));
    }
}
