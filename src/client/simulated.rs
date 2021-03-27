use crate::client::Client;
use p256::{PublicKey, SecretKey, ProjectivePoint, AffinePoint, Scalar};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::iter::Iterator;
use rand::RngCore;

pub struct SimulatedClient {
    rng: OsRng,
    identity_secret: SecretKey,
    caching_secret: Vec<u8>,
    group_size: usize,
    group_secret: Option<SecretKey>,
    group_commitments: Vec<Vec<u8>>,
    group_key: Option<PublicKey>,
    cache_counter: u16
}

impl SimulatedClient {
    pub fn new() -> Self {
        let mut rng = OsRng::default();
        let mut caching_secret = Vec::with_capacity(32);
        caching_secret.resize(32, 0);
        rng.fill_bytes(&mut caching_secret);
        SimulatedClient {
            rng,
            identity_secret: SecretKey::random(rng),
            caching_secret,
            group_size: 0,
            group_secret: None,
            group_commitments: Vec::new(),
            group_key: None,
            cache_counter: 0
        }
    }

    fn prf(&self, counter: u16) -> SecretKey {
        let mut hasher = Sha256::new();
        hasher.update(&self.caching_secret);
        hasher.update(u16::to_be_bytes(counter));
        let output = hasher.finalize();
        SecretKey::from_bytes(&output).unwrap()
    }

    fn kdf(&self, secret: &SecretKey) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(secret.to_bytes());
        let mut result = hasher.finalize().to_vec();
        let mut hasher = Sha256::new();
        hasher.update(&result);
        result.extend(hasher.finalize());
        result
    }
}

impl Client for SimulatedClient {
    fn get_info(&mut self) -> Result<String, String> {
        Ok(format!("SimulatedClient {}", env!("CARGO_PKG_VERSION")))
    }

    fn get_identity_key(&mut self) -> Result<PublicKey, String> {
        Ok(self.identity_secret.public_key())
    }

    fn keygen_initialize(&mut self, group_size: usize) -> Result<Vec<u8>, String> {
        self.group_size = group_size;
        self.group_secret = Some(SecretKey::random(self.rng));
        let group_public = self.group_secret.as_ref().unwrap().public_key();
        Ok(hash_point(&group_public))
    }

    fn keygen_reveal(&mut self, commitments: Vec<Vec<u8>>) -> Result<PublicKey, String> {
        assert_eq!(self.group_size, commitments.len());
        self.group_commitments = commitments;
        Ok(self.group_secret.as_ref().unwrap().public_key())
    }

    fn keygen_finalize(&mut self, public_keys: Vec<PublicKey>) -> Result<PublicKey, String> {
        assert_eq!(self.group_size, public_keys.len());
        for i in 0..self.group_size {
            let hash = hash_point(&public_keys.get(i).unwrap());
            let commitment = self.group_commitments.get(i).unwrap();
            assert_eq!(hash.len(), commitment.len());
            for (l, r) in hash.iter().zip(commitment) {
                assert_eq!(l, r);
            }
        }
        self.group_key = Some(PublicKey::from_affine(
            public_keys.iter()
                .map(PublicKey::to_projective)
                .fold(ProjectivePoint::identity(), |acc, x| acc + x)
                .to_affine()
        ).unwrap());
        Ok(self.group_key.unwrap())
    }

    fn get_nonce(&mut self, counter: u16) -> Result<PublicKey, String> {
        assert!(self.cache_counter <= counter);
        self.cache_counter = counter;
        Ok(self.prf(counter).public_key())
    }

    fn cache_nonce(&mut self, counter: u16) -> Result<Vec<u8>, String> {
        let nonce = self.prf(counter);
        let key = self.kdf(&nonce);
        assert_eq!(key.len(), 64);
        Ok(key.iter()
            .zip(nonce.public_key().to_encoded_point(false).as_bytes()[1..].iter())
            .map(|(l, r)| *l ^ *r)
            .collect())
    }

    fn reveal_nonce(&mut self, counter: u16) -> Result<Vec<u8>, String> {
        assert!(self.cache_counter <= counter);
        self.cache_counter = counter;
        Ok(self.kdf(&self.prf(counter)))
    }

    fn sign(&mut self, counter: u16, nonce_point: AffinePoint, message: [u8; 32]) -> Result<Scalar, String> {
        assert!(counter >= self.cache_counter);
        let &nonce = self.prf(counter).secret_scalar();
        let challenge = compute_challenge(self.group_key.unwrap(), nonce_point, message);
        let product = challenge.mul(self.group_secret.as_ref().unwrap().secret_scalar());
        let signature = nonce.add(&product);
        Ok(Scalar::from_bytes_reduced(&signature.to_bytes()))
    }

    fn sign_reveal(&mut self, counter: u16, nonce_point: AffinePoint, message: [u8; 32]) -> (Scalar, Vec<u8>) {
        (self.sign(counter, nonce_point, message).unwrap(), self.reveal_nonce(counter + 1).unwrap())
    }
}

fn hash_point(point: &PublicKey) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(point.to_encoded_point(false).to_bytes());
    hasher.finalize().to_vec()
}

pub fn compute_challenge(group_key: PublicKey, nonce_point: AffinePoint, message: [u8; 32]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(group_key.to_encoded_point(false).as_bytes());
    hasher.update(nonce_point.to_encoded_point(false).as_bytes());
    hasher.update(message);
    Scalar::from_bytes_reduced(&hasher.finalize())
}