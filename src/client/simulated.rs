use crate::client::Client;
use p256::{PublicKey, SecretKey, ProjectivePoint};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::iter::Iterator;

pub struct SimulatedClient {
    rng: OsRng,
    identity_secret: SecretKey,
    group_size: usize,
    group_secret: Option<SecretKey>,
    group_commitments: Vec<Vec<u8>>,
    group_key: Option<PublicKey>
}

impl SimulatedClient {
    pub fn new() -> Self {
        let rng = OsRng::default();
        SimulatedClient {
            rng,
            identity_secret: SecretKey::random(rng),
            group_size: 0,
            group_secret: None,
            group_commitments: Vec::new(),
            group_key: None
        }
    }
}

impl Client for SimulatedClient {
    fn get_info(&mut self) -> Result<String, String> {
        Ok(String::from("SimulatedClient 0.1.0"))
    }

    fn get_identity_key(&mut self) -> PublicKey {
        self.identity_secret.public_key()
    }

    fn keygen_initialize(&mut self, group_size: usize) -> Vec<u8> {
        self.group_size = group_size;
        self.group_secret = Some(SecretKey::random(self.rng));
        let group_public = self.group_secret.as_ref().unwrap().public_key();
        hash_point(&group_public)
    }

    fn keygen_reveal(&mut self, commitments: Vec<Vec<u8>>) -> PublicKey {
        assert_eq!(self.group_size, commitments.len());
        self.group_commitments = commitments;
        self.group_secret.as_ref().unwrap().public_key()
    }

    fn keygen_finalize(&mut self, public_keys: Vec<PublicKey>) -> PublicKey {
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
        self.group_key.unwrap()
    }
}

fn hash_point(point: &PublicKey) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(point.to_encoded_point(false).to_bytes());
    hasher.finalize().to_vec()
}