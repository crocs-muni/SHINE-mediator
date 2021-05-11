use crate::client::Client;
use crate::client::simulated::{hash_point, compute_delin, combine_prenonces};
use crate::protocol::{ProtocolMessage, ProtocolData, KeygenCommitment, SchnorrSerial, SchnorrSerialData, SchnorrCommitment, SchnorrCommitmentData, Protocol, SchnorrDelin, SchnorrDelinData};
use p256::{PublicKey, Scalar, ProjectivePoint, SecretKey};
use crate::client;
use std::ops::{Mul, Sub};
use crate::client::simulated::fold_points;
use rand::rngs::OsRng;

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

    pub fn broadcast(&mut self, message: ProtocolMessage) -> Vec<ProtocolData> {
        self.clients.iter_mut().map(|x| x.process(message.clone())).collect()
    }

    pub fn keygen_commitment(&mut self, parties: usize) -> PublicKey {
        let msg = ProtocolMessage::KeygenCommitment(KeygenCommitment::Initialize(parties));
        let commitments = self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_bytes)
            .collect();
        let msg = ProtocolMessage::KeygenCommitment(KeygenCommitment::Reveal(commitments));
        let public_keys: Vec<_> = self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_public_key)
            .collect();
        let msg = ProtocolMessage::KeygenCommitment(KeygenCommitment::Finalize(public_keys));
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
        let msg = ProtocolMessage::SchnorrSerial(SchnorrSerial::GetNonce(counter));
        let nonce_points: Vec<_> = self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_public_key)
            .collect();
        let aggregate_nonce = fold_points(&nonce_points);
        let msg = ProtocolMessage::SchnorrSerial(SchnorrSerial::Sign(counter, aggregate_nonce.clone(), message));
        let signatures: Vec<_> = self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_scalar)
            .collect();

        let signature = signatures.iter().fold(Scalar::zero(), |acc, x| acc + x);

        (aggregate_nonce, signature)
    }

    pub fn schnorr_serial_cache(&mut self, counter: u16) -> Vec<Vec<u8>> {
        let msg = ProtocolMessage::SchnorrSerial(SchnorrSerial::CacheNonce(counter));
        self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_bytes)
            .collect()
    }

    pub fn schnorr_serial_reveal(&mut self, counter: u16) -> Vec<Vec<u8>> {
        let msg = ProtocolMessage::SchnorrSerial(SchnorrSerial::RevealNonce(counter));
        self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_bytes)
            .collect()
    }

    pub fn schnorr_serial_nonce(&mut self, counter: u16) -> Vec<PublicKey> {
        let msg = ProtocolMessage::SchnorrSerial(SchnorrSerial::GetNonce(counter));
        self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_public_key)
            .collect()
    }

    pub fn schnorr_serial_sign_reveal(&mut self, counter: u16, nonce: PublicKey, message: [u8; 32]) -> ((PublicKey, Scalar), Vec<Vec<u8>>) {
        let msg = ProtocolMessage::SchnorrSerial(SchnorrSerial::SignReveal(counter, nonce.clone(), message));
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
        let msg = ProtocolMessage::SchnorrCommitment(SchnorrCommitment::CommitNonce(message));
        self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_bytes)
            .collect()
    }

    pub fn schnorr_commitment_reveal(&mut self, commitments: Vec<Vec<u8>>) -> Vec<PublicKey> {
        let msg = ProtocolMessage::SchnorrCommitment(SchnorrCommitment::RevealNonce(commitments));
        self.broadcast(msg)
            .into_iter()
            .map(ProtocolData::expect_public_key)
            .collect()
    }

    pub fn schnorr_commitment_sign(&mut self, nonce_points: Vec<PublicKey>) -> (PublicKey, Scalar) {
        let aggregate_nonce = fold_points(&nonce_points);
        let mut signature = Scalar::zero();

        let msg = ProtocolMessage::SchnorrCommitment(SchnorrCommitment::Sign(nonce_points));
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

    pub fn schnorr_delin_prenonces(&mut self) -> Vec<(PublicKey, PublicKey)> {
        let msg = ProtocolMessage::SchnorrDelin(SchnorrDelin::GetPrenonces);
        self.broadcast(msg)
            .into_iter()
            .map(|x| match x {
                ProtocolData::SchnorrDelin(SchnorrDelinData::Prenonces(prenonces)) => prenonces,
                _ => panic!(),
            })
            .collect()
    }

    pub fn schnorr_delin_sign(&mut self, prenonces: Vec<(PublicKey, PublicKey)>, message: [u8; 32]) -> (PublicKey, Scalar) {
        let mut aggregate_nonce = None;
        let mut signature = Scalar::zero();

        let msg = ProtocolMessage::SchnorrDelin(SchnorrDelin::Sign(prenonces, message));
        for data in self.broadcast(msg) {
            if let ProtocolData::SchnorrDelin(SchnorrDelinData::Signature(nonce_point, s)) = data {
                if aggregate_nonce.is_none() {
                    aggregate_nonce = Some(nonce_point);
                }
                signature = signature.add(&s);
                assert_eq!(nonce_point, aggregate_nonce.unwrap());
            } else {
                panic!();
            }
        }
        (aggregate_nonce.unwrap(), signature)

    }

    pub fn interop_commit_sign(&mut self, counter: u16, message: [u8; 32]) -> (PublicKey, Scalar) {
        let mut serial_clients = Vec::new();
        let mut commitment_clients = Vec::new();
        for (idx, client) in self.clients.iter().enumerate() {
            if client.is_supported(Protocol::SchnorrSerial) {
                serial_clients.push(idx);
            } else if client.is_supported(Protocol::SchnorrCommitment) {
                commitment_clients.push(idx);
            } else {
                panic!();
            }
        }

        let mut nonces = Vec::new();
        for idx in &serial_clients {
            let msg = ProtocolMessage::SchnorrSerial(SchnorrSerial::GetNonce(counter));
            nonces.push(self.clients[*idx].process(msg).expect_public_key());
        }

        let mut commitments: Vec<_> = nonces.iter().map(hash_point).collect();

        for idx in &commitment_clients {
            let msg = ProtocolMessage::SchnorrCommitment(SchnorrCommitment::CommitNonce(message));
            commitments.push(self.clients[*idx].process(msg).expect_bytes());
        }

        for idx in &commitment_clients {
            let msg = ProtocolMessage::SchnorrCommitment(SchnorrCommitment::RevealNonce(commitments.clone()));
            nonces.push(self.clients[*idx].process(msg).expect_public_key());
        }

        let nonce = fold_points(&nonces);

        let mut signatures = Vec::new();
        for idx in &serial_clients {
            let msg = ProtocolMessage::SchnorrSerial(SchnorrSerial::Sign(counter, nonce.clone(), message));
            signatures.push(self.clients[*idx].process(msg).expect_scalar());
        }
        for idx in &commitment_clients {
            let msg = ProtocolMessage::SchnorrCommitment(SchnorrCommitment::Sign(nonces.clone()));
            signatures.push(self.clients[*idx].process(msg).expect_scalar());
        }

        let signature = signatures.iter().fold(Scalar::zero(), |acc, x| acc + x);

        (nonce, signature)
    }

    pub fn interop_delin_sign(&mut self, counter: u16, message: [u8; 32]) -> (PublicKey, Scalar) {
        let mut serial_clients = Vec::new();
        let mut delin_clients = Vec::new();
        for (idx, client) in self.clients.iter().enumerate() {
            if client.is_supported(Protocol::SchnorrSerial) {
                serial_clients.push(idx);
            } else if client.is_supported(Protocol::SchnorrDelin) {
                delin_clients.push(idx);
            } else {
                panic!();
            }
        }

        let mut nonces = Vec::new();
        for idx in &serial_clients {
            let msg = ProtocolMessage::SchnorrSerial(SchnorrSerial::GetNonce(counter));
            nonces.push(self.clients[*idx].process(msg).expect_public_key());
        }
        let rng = OsRng::default();
        let simulated_nonces: Vec<_> = (0..nonces.len()).map(|_| SecretKey::random(rng)).collect();
        let mut prenonces: Vec<(PublicKey, PublicKey)> = nonces.into_iter()
            .zip(simulated_nonces.clone())
            .map(|(x,y): (PublicKey, SecretKey)| {
                return (x, y.public_key())
            })
            .collect();


        for idx in &delin_clients {
            let msg = ProtocolMessage::SchnorrDelin(SchnorrDelin::GetPrenonces);
            if let ProtocolData::SchnorrDelin(SchnorrDelinData::Prenonces(data)) = self.clients[*idx].process(msg) {
                prenonces.push(data);
            } else {
                panic!();
            }
        }

        let (coeff, nonce) = compute_delin(&combine_prenonces(&prenonces), message);

        let mut signatures = Vec::new();
        for idx in &serial_clients {
            let msg = ProtocolMessage::SchnorrSerial(SchnorrSerial::Sign(counter, nonce.clone(), message));
            signatures.push(self.clients[*idx].process(msg).expect_scalar());
        }
        for idx in &delin_clients {
            let msg = ProtocolMessage::SchnorrDelin(SchnorrDelin::Sign(prenonces.clone(), message));
            signatures.push(self.clients[*idx].process(msg).expect_scalar());
        }

        let mut signature = signatures.iter().fold(Scalar::zero(), |acc, x| acc + x);
        for simulated_nonce in simulated_nonces {
            signature += coeff.mul(simulated_nonce.secret_scalar() as &Scalar)
        }
        (nonce, signature)
    }
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
