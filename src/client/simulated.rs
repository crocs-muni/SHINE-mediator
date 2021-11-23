use crate::client::Client;
use k256::{PublicKey, SecretKey, ProjectivePoint, Scalar};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use std::iter::Iterator;
use rand::RngCore;
use crate::protocol::{KeygenCommit, ProtocolMessage, ProtocolData, KeygenCommitData, SchnorrExchange, SchnorrExchangeData, SchnorrCommitData, SchnorrCommit, Protocol, SchnorrDelin, SchnorrDelinData};
use std::ops::Mul;
use crate::proto::ProtocolIdentifier;

pub struct SimulatedClient {
    rng: OsRng,
    identity_secret: SecretKey,
    group_size: usize,
    group_secret: Option<SecretKey>,
    group_commitments: Vec<Vec<u8>>,
    group_key: Option<PublicKey>,

    cache_secret: Vec<u8>,
    cache_counter: u16,

    commitment_message: [u8; 32],
    commitment_secret: Option<SecretKey>,
    commitment_hashes: Vec<Vec<u8>>,

    delin_prenonces: Option<(SecretKey, SecretKey)>,
}

impl SimulatedClient {
    pub fn new() -> Self {
        let mut rng = OsRng::default();
        let mut cache_secret = Vec::with_capacity(32);
        cache_secret.resize(32, 0);
        rng.fill_bytes(&mut cache_secret);
        SimulatedClient {
            rng,
            identity_secret: SecretKey::random(rng),
            group_size: 0,
            group_secret: None,
            group_commitments: Vec::new(),
            group_key: None,
            cache_secret,
            cache_counter: 0,
            commitment_message: [0; 32],
            commitment_secret: None,
            commitment_hashes: Vec::new(),
            delin_prenonces: None,
        }
    }

    fn prf(&self, counter: u16) -> SecretKey {
        let mut hasher = Sha256::new();
        hasher.update(&self.cache_secret);
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

    fn handle_keygen_commitment(&mut self, message: KeygenCommit) -> KeygenCommitData {
        match message {
            KeygenCommit::Initialize(group_size) => {
                self.group_size = group_size;
                self.group_secret = Some(SecretKey::random(self.rng));
                let group_public = self.group_secret.as_ref().unwrap().public_key();
                KeygenCommitData::Commitment(hash_point(&group_public))
            },
            KeygenCommit::Reveal(commitments) => {
                assert_eq!(self.group_size, commitments.len());
                self.group_commitments = commitments;
                KeygenCommitData::Reveal(self.group_secret.as_ref().unwrap().public_key())
            },
            KeygenCommit::Finalize(public_keys) => {
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
                KeygenCommitData::Result(self.group_key.unwrap())
            }
        }
    }

    fn handle_schnorr_serial(&mut self, message: SchnorrExchange) -> SchnorrExchangeData {
        match message {
            SchnorrExchange::GetNonce(counter) => {
                assert!(self.cache_counter <= counter);
                self.cache_counter = counter;
                SchnorrExchangeData::Nonce(self.prf(counter).public_key())
            },
            SchnorrExchange::CacheNonce(counter) => {
                let nonce = self.prf(counter);
                let key = self.kdf(&nonce);
                assert_eq!(key.len(), 64);
                SchnorrExchangeData::EncryptedNonce(key.iter()
                    .zip(nonce.public_key().to_encoded_point(false).as_bytes()[1..].iter())
                    .map(|(l, r)| *l ^ *r)
                    .collect())
            },
            SchnorrExchange::RevealNonce(counter) => {
                SchnorrExchangeData::NonceKey(self.schnorr_reveal(counter))
            },
            SchnorrExchange::Sign(counter, nonce_point, message) => {
                SchnorrExchangeData::Signature(self.schnorr_sign(counter, nonce_point, message))
            },
            SchnorrExchange::SignReveal(counter, nonce_point, message) => {
                SchnorrExchangeData::SignatureNonceKey(
                    self.schnorr_sign(counter, nonce_point, message),
                    self.schnorr_reveal(counter + 1)
                )
            }
        }
    }

    fn handle_schnorr_commitment(&mut self, message: SchnorrCommit) -> SchnorrCommitData {
        match message {
            SchnorrCommit::CommitNonce(message) => {
                self.commitment_message = message;
                self.commitment_secret = Some(SecretKey::random(self.rng));
                SchnorrCommitData::Commitment(hash_point(&self.commitment_secret.as_ref().unwrap().public_key()))
            },
            SchnorrCommit::RevealNonce(commitments) => {
                assert!(self.commitment_secret.is_some());
                self.commitment_hashes = commitments;
                SchnorrCommitData::Reveal(self.commitment_secret.as_ref().unwrap().public_key())
            },
            SchnorrCommit::Sign(nonces) => {
                assert_eq!(self.commitment_hashes.len(), nonces.len());
                for (nonce_point, commitment) in nonces.iter().zip(self.commitment_hashes.iter()) {
                    assert_eq!(&hash_point(nonce_point), commitment);
                }

                let nonce_point = fold_points(&nonces);
                let nonce = self.commitment_secret.as_ref().unwrap().to_secret_scalar();
                let challenge = compute_challenge(&nonce_point, &self.group_key.unwrap(), self.commitment_message);
                let product = challenge.mul(&self.group_secret.as_ref().unwrap().to_secret_scalar() as &Scalar);
                let signature = nonce.add(&product);

                self.commitment_message.iter_mut().for_each(|x| *x = 0);
                self.commitment_secret = None;
                self.commitment_hashes = Vec::new();

                SchnorrCommitData::Signature(nonce_point, Scalar::from_bytes_reduced(&signature.to_bytes()))
            },
        }
    }

    fn handle_schnorr_delin(&mut self, message: SchnorrDelin) -> SchnorrDelinData {
        match message {
            SchnorrDelin::GetPrenonces => {
                self.delin_prenonces = Some((SecretKey::random(self.rng), SecretKey::random(self.rng)));
                SchnorrDelinData::Prenonces((
                    self.delin_prenonces.as_ref().unwrap().0.public_key(),
                    self.delin_prenonces.as_ref().unwrap().1.public_key()
                ))
            },
            SchnorrDelin::Sign(prenonces, message) => {
                let prenonces = combine_prenonces(&prenonces);
                let (coeff, nonce_point) = compute_delin(&prenonces, message);
                let nonce = &self.delin_prenonces.as_ref().unwrap().0.to_secret_scalar() as &Scalar;
                let nonce = nonce + &coeff.mul(&self.delin_prenonces.as_ref().unwrap().1.to_secret_scalar() as &Scalar);
                let challenge = compute_challenge(&nonce_point, &self.group_key.unwrap(), message);
                let product = challenge.mul(&self.group_secret.as_ref().unwrap().to_secret_scalar() as &Scalar);
                let signature = nonce.add(&product);
                SchnorrDelinData::Signature(nonce_point, Scalar::from_bytes_reduced(&signature.to_bytes()))
            }
        }
    }

    fn schnorr_sign(&mut self, counter: u16, nonce_point: PublicKey, message: [u8; 32]) -> Scalar {
        assert!(counter >= self.cache_counter);
        let nonce = self.prf(counter).to_secret_scalar();
        let challenge = compute_challenge(&nonce_point, &self.group_key.unwrap(), message);
        let product = challenge.mul(&self.group_secret.as_ref().unwrap().to_secret_scalar() as &Scalar);
        let signature = nonce.add(&product);
        Scalar::from_bytes_reduced(&signature.to_bytes())
    }

    fn schnorr_reveal(&mut self, counter: u16) -> Vec<u8> {
        assert!(self.cache_counter <= counter);
        self.cache_counter = counter;
        self.kdf(&self.prf(counter))
    }
}

impl Client for SimulatedClient {
    fn get_info(&mut self) -> Result<String, String> {
        Ok(format!("Simulator {}", env!("CARGO_PKG_VERSION")))
    }

    fn get_identity_key(&mut self) -> Result<PublicKey, String> {
        Ok(self.identity_secret.public_key())
    }

    fn get_supported(&self) -> Vec<ProtocolIdentifier> {
        vec![
            ProtocolIdentifier::Ecdsa,
            ProtocolIdentifier::Eddsa,
            ProtocolIdentifier::Bipschnorr,
        ]
    }

    fn process(&mut self, msg: ProtocolMessage) -> ProtocolData {
        match msg {
            ProtocolMessage::KeygenCommit(msg) => ProtocolData::KeygenCommit(self.handle_keygen_commitment(msg)),
            ProtocolMessage::SchnorrExchange(msg) => ProtocolData::SchnorrExchange(self.handle_schnorr_serial(msg)),
            ProtocolMessage::SchnorrCommit(msg) => ProtocolData::SchnorrCommit(self.handle_schnorr_commitment(msg)),
            ProtocolMessage::SchnorrDelin(msg) => ProtocolData::SchnorrDelin(self.handle_schnorr_delin(msg)),
        }
    }

    fn is_supported(&self, protocol: Protocol) -> bool {
        match protocol {
            Protocol::KeygenCommit => true,
            Protocol::SchnorrExchange => true,
            Protocol::SchnorrCommit => true,
            Protocol::SchnorrDelin => true,
        }
    }
}

pub fn hash_point(point: &PublicKey) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(point.to_encoded_point(false).to_bytes());
    hasher.finalize().to_vec()
}

pub fn compute_challenge(nonce_point: &PublicKey, group_key: &PublicKey, message: [u8; 32]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(nonce_point.to_encoded_point(false).as_bytes());
    hasher.update(group_key.to_encoded_point(false).as_bytes());
    hasher.update(message);
    Scalar::from_bytes_reduced(&hasher.finalize())
}

pub fn combine_prenonces(prenonces: &Vec<(PublicKey, PublicKey)>) -> (PublicKey, PublicKey) {
    let prenonces: (Vec<_>, Vec<_>) = (
        prenonces.iter().map(|x| x.0).collect(),
        prenonces.iter().map(|x| x.1).collect()
    );
    (fold_points(&prenonces.0), fold_points(&prenonces.1))
}

pub fn compute_delin(prenonces: &(PublicKey, PublicKey), message: [u8; 32]) -> (Scalar, PublicKey) {
    let mut hasher = Sha256::new();
    hasher.update(prenonces.0.to_encoded_point(false).as_bytes());
    hasher.update(prenonces.1.to_encoded_point(false).as_bytes());
    hasher.update(message);
    let coeff = Scalar::from_bytes_reduced(&hasher.finalize());
    let nonce_point = PublicKey::from_affine(
        (prenonces.0.to_projective() + prenonces.1.to_projective().mul(coeff)).to_affine()
    ).unwrap();
    (coeff, nonce_point)
}

pub fn fold_points(points: &[PublicKey]) -> PublicKey {
    PublicKey::from_affine(points.iter()
        .map(PublicKey::to_projective)
        .fold(ProjectivePoint::identity(), |acc, x| acc + x)
        .to_affine()
    ).unwrap()
}
