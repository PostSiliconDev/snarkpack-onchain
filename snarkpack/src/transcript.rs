use ark_ec::{AdditiveGroup, AffineRepr};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalSerialize, Compress};
use sha3::{Digest, Keccak256};

pub const SLOT_SIZE: usize = 32;

pub struct OnchainTranscript {
    state: Vec<u8>,
}

impl OnchainTranscript {
    /// Init a transcript
    pub fn new(msg: &'static [u8]) -> Self {
        let mut t = Self { state: Vec::new() };
        t.append_message(b"", msg);
        t
    }

    /// Append the message to the transcript. `_label` is omitted for efficiency.
    pub fn append_message(&mut self, _label: &'static [u8], msg: &[u8]) {
        if msg.len() < SLOT_SIZE {
            let mut tmp = vec![0; SLOT_SIZE];
            let index = SLOT_SIZE - msg.len();
            tmp[index..].copy_from_slice(msg);
            self.state.extend_from_slice(&tmp);
        } else {
            assert!(msg.len() % SLOT_SIZE == 0);
            self.state.extend_from_slice(msg);
        }
    }

    /// Append a single commitment/poiny to the transcript.
    pub fn append_point<G: AffineRepr>(&mut self, repr: &G) {
        let x: G::BaseField = repr.x().unwrap_or(G::BaseField::ZERO);
        let y: G::BaseField = repr.y().unwrap_or(G::BaseField::ZERO);

        let mut buf_x = vec![];
        x.serialize_with_mode(&mut buf_x, Compress::Yes).unwrap();
        buf_x.reverse();

        let mut buf_y = vec![];
        y.serialize_with_mode(&mut buf_y, Compress::Yes).unwrap();
        buf_y.reverse();

        buf_x.extend_from_slice(&buf_y);

        Self::append_message(self, b"", &buf_x);
    }

    /// Append a challenge/scalar to the transcript.
    pub fn append_scalar<F: Field>(&mut self, scalar: &F) {
        let mut buf_x = vec![];
        scalar
            .serialize_with_mode(&mut buf_x, Compress::Yes)
            .unwrap();
        buf_x.reverse();
        Self::append_message(self, b"", &buf_x);
    }

    /// Generate the challenge for the current transcript,
    /// and then append it to the transcript. `_label` is omitted for
    /// efficiency.
    pub fn get_challenge<F: PrimeField>(&mut self) -> F {
        let mut hasher = Keccak256::new();
        hasher.update(&self.state);
        let mut buf = hasher.finalize();
        buf.reverse();
        let challenge = F::from_le_bytes_mod_order(&buf);

        self.state = challenge.into_bigint().to_bytes_be();

        challenge
    }
}
