use ark_ec::{
    pairing::{MillerLoopOutput, Pairing, PairingOutput},
    CurveGroup,
};
use ark_ff::{Field, PrimeField};
use ark_std::{ops::Mul, rand::Rng, One, UniformRand, Zero};
use rayon::prelude::*;

use std::ops::MulAssign;

/// PairingCheck represents a check of the form e(A,B)e(C,D)... = T. Checks can
/// be aggregated together using random linear combination. The efficiency comes
/// from keeping the results from the miller loop output before proceding to a final
/// exponentiation when verifying if all checks are verified.
/// It is a tuple:
/// - a miller loop result that is to be multiplied by other miller loop results
/// before going into a final exponentiation result
/// - a right side result which is already in the right subgroup Gt which is to
/// be compared to the left side when "final_exponentiatiat"-ed
pub struct PairingCheck<E: Pairing, R: Rng> {
    left: E::TargetField,
    right: E::TargetField,
    /// simple counter tracking number of non_randomized checks. If there are
    /// more than 1 non randomized check, it is invalid.
    non_randomized: u8,
    rng: R,
}

impl<E: Pairing, R: Rng> PairingCheck<E, R> {
    pub fn new(rng: R) -> PairingCheck<E, R> {
        Self {
            left: E::TargetField::one(),
            right: E::TargetField::one(),
            non_randomized: 0,
            rng,
        }
    }

    /// Returns a pairing check from the output of the miller pairs and the
    /// expected right hand side such that the following must hold:
    /// $$
    ///   finalExponentiation(\Prod_i lefts[i]) = exp
    /// $$
    ///
    /// Note the check is NOT randomized and there must be only up to ONE check
    /// only that can not be randomized when merging.
    pub fn products(&mut self, lefts: Vec<E::TargetField>, right: E::TargetField) {
        let product = lefts
            .iter()
            .fold(<E as Pairing>::TargetField::one(), |mut acc, l| {
                acc *= l;
                acc
            });

        mul_if_not_one::<E>(&mut self.left, &product);
        mul_if_not_one::<E>(&mut self.right, &right);
        self.non_randomized += 1;
    }

    /// returns a pairing tuple that is scaled by a random element.
    /// When aggregating pairing checks, this creates a random linear
    /// combination of all checks so that it is secure. Specifically
    /// we have e(A,B)e(C,D)... = out <=> e(g,h)^{ab + cd} = out
    /// We rescale using a random element $r$ to give
    /// e(rA,B)e(rC,D) ... = out^r <=>
    /// e(A,B)^r e(C,D)^r = out^r <=> e(g,h)^{abr + cdr} = out^r
    /// (e(g,h)^{ab + cd})^r = out^r
    pub fn rand<'a>(
        &mut self,
        it: &[(&'a E::G1Affine, &'a E::G2Affine)],
        out: &'a <E as Pairing>::TargetField,
    ) {
        let coeff = rand_fr::<E, R>(&mut self.rng);
        let miller_out = it
            .into_par_iter()
            .map(|(a, b)| {
                let na = a.mul(coeff).into_affine();
                (E::G1Prepared::from(na), E::G2Prepared::from(**b))
            })
            .map(|(a, b)| E::miller_loop(a, b))
            .fold(
                || <E as Pairing>::TargetField::one(),
                |mut acc, res| {
                    acc.mul_assign(&(res.0));
                    acc
                },
            )
            .reduce(
                || <E as Pairing>::TargetField::one(),
                |mut acc, res| {
                    acc.mul_assign(&res);
                    acc
                },
            );
        let mut outt = out.clone();
        if out != &<E as Pairing>::TargetField::one() {
            // we only need to make this expensive operation is the output is
            // not one since 1^r = 1
            outt = outt.pow(&(coeff.into_bigint()));
        }

        mul_if_not_one::<E>(&mut self.left, &miller_out);
        mul_if_not_one::<E>(&mut self.right, &outt);
    }

    /// Returns false if there is more than 1 non-random check and otherwise
    /// returns true if
    /// $$
    ///   FinalExponentiation(left) == right
    /// $$
    pub fn verify(&self) -> bool {
        if self.non_randomized > 1 {
            dbg!(format!(
                "Pairing checks have more than 1 non-random checks {}",
                self.non_randomized
            ));
            return false;
        }
        E::final_exponentiation(MillerLoopOutput(self.left)) == Some(PairingOutput(self.right))
    }
}

fn rand_fr<E: Pairing, R: Rng>(rng: &mut R) -> E::ScalarField {
    loop {
        let c = E::ScalarField::rand(rng);
        if c != E::ScalarField::zero() {
            return c;
        }
    }
}

fn mul_if_not_one<E: Pairing>(left: &mut E::TargetField, right: &E::TargetField) {
    let one = E::TargetField::one();
    if left == &one {
        *left = right.clone();
        return;
    } else if right == &one {
        // nothing to do here
        return;
    }
    left.mul_assign(right);
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381 as Bls12, G1Projective, G2Projective};
    use ark_std::UniformRand;
    use rand_core::SeedableRng;

    #[test]
    fn test_pairing_randomize() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(0u64);
        let mut acc = PairingCheck::<Bls12, _>::new(rng.clone());
        for _ in 0..3 {
            let g1r = G1Projective::rand(&mut rng);
            let g2r = G2Projective::rand(&mut rng);
            let exp = Bls12::pairing(g1r.clone(), g2r.clone());

            acc.rand(&[(&g1r.into_affine(), &g2r.into_affine())], &exp.0);
        }

        assert!(acc.verify());
    }
}
