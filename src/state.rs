use crate::client::Client;
use crate::protocol::{Protocol, ProtocolData, KeygenCommitment, SchnorrSerial, SchnorrSerialData, SchnorrCommitment, SchnorrCommitmentData};
use p256::{PublicKey, Scalar, ProjectivePoint};
use crate::client;
use std::ops::{Mul, Sub};
use crate::client::simulated::fold_points;

pub struct State {
    pub clients: Vec<Box<dyn Client>>
}

impl State {
    pub fn new() -> State {
        State { clients: Vec::new() }
    }

    pub fn add_client(&mut self, client: Box<dyn Client>) {
        self.clients.push(client);
    }

    pub fn broadcast(&mut self, message: Protocol) -> Vec<ProtocolData> {
        self.clients.iter_mut().map(|x| x.process(message.clone())).collect()
    }

    pub fn keygen_commitment(&mut self, parties: usize) -> PublicKey {
        let msg = Protocol::KeygenCommitment(KeygenCommitment::Initialize(parties));
        let commitments = self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_bytes)
            .collect();
        let msg = Protocol::KeygenCommitment(KeygenCommitment::Reveal(commitments));
        let public_keys: Vec<_> = self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_public_key)
            .collect();
        let msg = Protocol::KeygenCommitment(KeygenCommitment::Finalize(public_keys));
        let mut group_keys = self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_public_key)
            .into_iter();
        let group_key = group_keys.next().unwrap();
        for other_group_key in group_keys {
            assert_eq!(group_key, other_group_key);
        }
        group_key
    }

    pub fn schnorr_serial_sign(&mut self, counter: u16, message: [u8; 32]) -> (PublicKey, Scalar) {
        let msg = Protocol::SchnorrSerial(SchnorrSerial::GetNonce(counter));
        let nonce_points: Vec<_> = self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_public_key)
            .collect();
        let aggregate_nonce = fold_points(&nonce_points);
        let msg = Protocol::SchnorrSerial(SchnorrSerial::Sign(counter, aggregate_nonce.clone(), message));
        let signatures: Vec<_> = self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_scalar)
            .collect();

        let signature = signatures.iter().fold(Scalar::zero(), |acc, x| acc + x);

        (aggregate_nonce, signature)
    }

    pub fn schnorr_serial_cache(&mut self, counter: u16) -> Vec<Vec<u8>> {
        let msg = Protocol::SchnorrSerial(SchnorrSerial::CacheNonce(counter));
        self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_bytes)
            .collect()
    }

    pub fn schnorr_serial_reveal(&mut self, counter: u16) -> Vec<Vec<u8>> {
        let msg = Protocol::SchnorrSerial(SchnorrSerial::RevealNonce(counter));
        self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_bytes)
            .collect()
    }

    pub fn schnorr_serial_nonce(&mut self, counter: u16) -> Vec<PublicKey> {
        let msg = Protocol::SchnorrSerial(SchnorrSerial::GetNonce(counter));
        self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_public_key)
            .collect()
    }

    pub fn schnorr_serial_sign_reveal(&mut self, counter: u16, nonce: PublicKey, message: [u8; 32]) -> ((PublicKey, Scalar), Vec<Vec<u8>>) {
        let msg = Protocol::SchnorrSerial(SchnorrSerial::SignReveal(counter, nonce.clone(), message));
        let mut signature = Scalar::zero();
        let mut decryption_keys: Vec<Vec<u8>> = Vec::new();
        for response in self.broadcast(msg) {
            if let ProtocolData::SchnorrSerial(SchnorrSerialData::SignatureNonceKey(sign, decryption_key)) = response {
                signature = signature.add(&sign);
                decryption_keys.push(decryption_key);
            } else {
                panic!()
            }
        }
        ((nonce, signature), decryption_keys)
    }

    pub fn schnorr_commitment_commit(&mut self, message: [u8; 32]) -> Vec<Vec<u8>> {
        let msg = Protocol::SchnorrCommitment(SchnorrCommitment::CommitNonce(message));
        self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_bytes)
            .collect()
    }

    pub fn schnorr_commitment_reveal(&mut self, commitments: Vec<Vec<u8>>) -> Vec<PublicKey> {
        let msg = Protocol::SchnorrCommitment(SchnorrCommitment::RevealNonce(commitments));
        self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_public_key)
            .collect()
    }

    pub fn schnorr_commitment_sign(&mut self, nonce_points: Vec<PublicKey>) -> (PublicKey, Scalar) {
        let aggregate_nonce = fold_points(&nonce_points);
        let mut signature = Scalar::zero();

        let msg = Protocol::SchnorrCommitment(SchnorrCommitment::Sign(nonce_points));
        for data in self.broadcast(msg) {
            if let ProtocolData::SchnorrCommitment(SchnorrCommitmentData::Signature(nonce_point, s)) = data {
                signature = signature.add(&s);
                assert_eq!(nonce_point, aggregate_nonce);
            } else {
                panic!();
            }
        }
        (aggregate_nonce, signature)
    }

    pub fn decrypt_nonces(encrypted_nonces: Vec<Vec<u8>>, decryption_keys: Vec<Vec<u8>>) -> Vec<PublicKey> {
        let mut decrypted_nonces = Vec::new();
        for (encrypted_nonce, decryption_key) in encrypted_nonces.iter().zip(decryption_keys.iter()) {
            assert_eq!(encrypted_nonce.len(), decryption_key.len());
            let mut point = vec![0x04];
            point.extend(
                encrypted_nonce.iter()
                    .zip(decryption_key.iter())
                    .map(|(l, r)| *l ^ *r)
            );
            decrypted_nonces.push(PublicKey::from_sec1_bytes(&point).unwrap());
        }
        decrypted_nonces
    }

    pub fn schnorr_verify(signature: (PublicKey, Scalar), message: [u8; 32], public_key: &PublicKey) -> bool {
        let (nonce, signature) = signature;

        let challenge = client::simulated::compute_challenge(public_key, &nonce, message);
        let verif_point = ProjectivePoint::generator().mul(signature).sub(public_key.to_projective().mul(challenge)).to_affine();

        &verif_point == nonce.as_affine()
    }

}