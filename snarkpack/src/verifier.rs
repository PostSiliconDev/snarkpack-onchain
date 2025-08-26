use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_groth16::PreparedVerifyingKey;
use ark_std::{rand::Rng, One, Zero};
use std::ops::{AddAssign, Mul, MulAssign, Neg, SubAssign};

use super::{
    commitment::Output,
    pairing_check::PairingCheck,
    proof::{AggregateProof, KZGOpening},
    prover::polynomial_evaluation_product_form_from_transcript,
    srs::VerifierSRS,
    transcript::OnchainTranscript,
};
use crate::Error;

/// Verifies the aggregated proofs thanks to the Groth16 verifying key, the
/// verifier SRS from the aggregation scheme, all the public inputs of the
/// proofs and the aggregated proof.
///
/// WARNING: transcript_include represents everything that should be included in
/// the transcript from outside the boundary of this function. This is especially
/// relevant for ALL public inputs of ALL individual proofs. In the regular case,
/// one should input ALL public inputs from ALL proofs aggregated. However, IF ALL the
/// public inputs are **fixed, and public before the aggregation time**, then there is
/// no need to hash those. The reason we specify this extra assumption is because hashing
/// the public inputs from the decoded form can take quite some time depending on the
/// number of proofs and public inputs (+100ms in our case). In the case of Filecoin, the only
/// non-fixed part of the public inputs are the challenges derived from a seed. Even though this
/// seed comes from a random beeacon, we are hashing this as a safety precaution.
pub fn verify_aggregate_proof<E: Pairing, R: Rng>(
    ip_verifier_srs: &VerifierSRS<E>,
    pvk: &PreparedVerifyingKey<E>,
    public_inputs: &[Vec<E::ScalarField>],
    proof: &AggregateProof<E>,
    rng: R,
) -> Result<(), Error> {
    proof.parsing_check()?;
    for pub_input in public_inputs {
        if (pub_input.len() + 1) != pvk.vk.gamma_abc_g1.len() {
            return Err(Error::MalformedVerifyingKey);
        }
    }

    if public_inputs.len() != proof.tmipp.gipa.nproofs as usize {
        return Err(Error::InvalidProof(
            "public inputs len != number of proofs".to_string(),
        ));
    }

    // 1. Random linear combination of proofs
    let mut transcript = OnchainTranscript::new(b"snarkpack-onchain");
    // TODO append publics hash
    transcript.append_scalar(&proof.com_ab.0);
    transcript.append_scalar(&proof.com_ab.1);
    transcript.append_scalar(&proof.com_c.0);
    transcript.append_scalar(&proof.com_c.1);
    let r = transcript.get_challenge::<E::ScalarField>();

    // Continuous loop that aggregate pairing checks together
    let mut acc = PairingCheck::new(rng);

    // 2.Check TIPA proof
    verify_tipp_mipp(ip_verifier_srs, proof, &r, &mut transcript, &mut acc)?;

    // Check aggregate pairing product equation
    // SUM of a geometric progression
    // SUM a^i = (1 - a^n) / (1 - a) = -(1-a^n)/-(1-a)
    // = (a^n - 1) / (a - 1)
    let mut r_sum = r.pow(&[public_inputs.len() as u64]);
    r_sum.sub_assign(&E::ScalarField::one());
    let b = sub!(r, &E::ScalarField::one()).inverse().unwrap();
    r_sum.mul_assign(&b);

    // The following parts 3 4 5 are independently computing the parts of
    // the Groth16 verification equation NOTE From this point on, we are
    // only checking *one* pairing check (the Groth16 verification equation)
    // so we don't need to randomize as all other checks are being
    // randomized already. When merging all pairing checks together, this
    // will be the only one non-randomized.
    // 3. Compute left part of the final pairing equation
    let left = {
        let alpha_g1_r_suma = pvk.vk.alpha_g1;
        let alpha_g1_r_sum = alpha_g1_r_suma.mul(r_sum);

        E::miller_loop(
            E::G1Prepared::from(alpha_g1_r_sum.into()),
            E::G2Prepared::from(pvk.vk.beta_g2),
        )
    };

    // 4. Compute right part of the final pairing equation
    let right = E::miller_loop(
        // e(c^r vector form, h^delta)
        E::G1Prepared::from(proof.agg_c),
        E::G2Prepared::from(pvk.vk.delta_g2),
    );

    // 5. compute the middle part of the final pairing equation, the one with the public inputs
    let middle = {
        // We want to compute MUL(i:0 -> l) S_i ^ (SUM(j:0 -> n) ai,j * r^j)
        // this table keeps tracks of incremental computation of each i-th
        // exponent to later multiply with S_i
        // The index of the table is i, which is an index of the public
        // input element
        // We incrementally build the r vector and the table
        // NOTE: in this version it's not r^2j but simply r^j

        let mut g_ic: E::G1 = pvk.vk.gamma_abc_g1[0].into();
        g_ic.mul_assign(r_sum);
        g_ic.add_assign(&proof.totsi);

        E::miller_loop(
            E::G1Prepared::from(g_ic.into_affine()),
            E::G2Prepared::from(pvk.vk.gamma_g2.clone()),
        )
    };

    // final value ip_ab is what we want to compare in the groth16 aggregated equation A * B
    acc.products(vec![left.0, middle.0, right.0], proof.ip_ab.clone());

    if acc.verify() {
        Ok(())
    } else {
        Err(Error::InvalidProof("Proof Verification Failed".to_string()))
    }
}

/// verify_tipp_mipp returns a pairing equation to check the tipp proof.  $r$ is
/// the randomness used to produce a random linear combination of A and B and
/// used in the MIPP part with C
fn verify_tipp_mipp<E: Pairing, R: Rng>(
    v_srs: &VerifierSRS<E>,
    proof: &AggregateProof<E>,
    r_shift: &E::ScalarField,
    transcript: &mut OnchainTranscript,
    acc: &mut PairingCheck<E, R>,
) -> Result<(), Error> {
    // (T,U), Z for TIPP and MIPP  and all challenges
    let (final_res, final_r, challenges, challenges_inv) =
        gipa_verify_tipp_mipp(&proof, r_shift, transcript);

    // Verify commitment keys wellformed
    let fvkey = proof.tmipp.gipa.final_vkey;
    let fwkey = proof.tmipp.gipa.final_wkey;

    // KZG challenge point
    transcript.append_scalar(&challenges[0]);
    transcript.append_point(&proof.tmipp.gipa.final_vkey.0);
    transcript.append_point(&proof.tmipp.gipa.final_vkey.1);
    transcript.append_point(&proof.tmipp.gipa.final_wkey.0);
    transcript.append_point(&proof.tmipp.gipa.final_wkey.1);
    let c = transcript.get_challenge::<E::ScalarField>();

    // we take reference so they are able to be copied in the par! macro
    let final_a = &proof.tmipp.gipa.final_a;
    let final_b = &proof.tmipp.gipa.final_b;
    let final_c = &proof.tmipp.gipa.final_c;
    let final_zab = &final_res.zab;
    let final_tab = &final_res.tab;
    let final_uab = &final_res.uab;
    let final_tc = &final_res.tc;
    let final_uc = &final_res.uc;

    // check the opening proof for v
    verify_kzg_v(
        v_srs,
        &fvkey,
        &proof.tmipp.vkey_opening,
        &challenges_inv,
        &c,
        acc,
    );

    // check the opening proof for w - note that w has been rescaled by $r^{-1}$
    verify_kzg_w(
        v_srs,
        &fwkey,
        &proof.tmipp.wkey_opening,
        &challenges,
        &r_shift.inverse().unwrap(),
        &c,
        acc,
    );

    //
    // We create a sequence of pairing tuple that we aggregate together at
    // the end to perform only once the final exponentiation.
    //
    // TIPP
    // z = e(A,B)
    acc.rand(&[(final_a, final_b)], final_zab);

    // final_aB.0 = T = e(A,v1)e(w1,B)
    acc.rand(&[(final_a, &fvkey.0), (&fwkey.0, final_b)], final_tab);

    // final_aB.1 = U = e(A,v2)e(w2,B)
    acc.rand(&[(final_a, &fvkey.1), (&fwkey.1, final_b)], final_uab);

    // MIPP
    // T = e(C,v1)
    acc.rand(&[(final_c, &fvkey.0)], final_tc);

    // U = e(A,v2)
    acc.rand(&[(final_c, &fvkey.1)], final_uc);

    // Check commiment correctness
    // Verify base inner product commitment
    // Z ==  c ^ r
    if final_res.zc != final_c.mul(final_r) {
        Err(Error::InvalidProof("TIPP verification failed".to_string()))
    } else {
        Ok(())
    }
}

/// gipa_verify_tipp_mipp recurse on the proof and statement and produces the final
/// values to be checked by TIPP and MIPP verifier, namely, for TIPP for example:
/// * T,U: the final commitment values of A and B
/// * Z the final product between A and B.
/// * Challenges are returned in inverse order as well to avoid
/// repeating the operation multiple times later on.
/// * There are T,U,Z vectors as well for the MIPP relationship. Both TIPP and
/// MIPP share the same challenges however, enabling to re-use common operations
/// between them, such as the KZG proof for commitment keys.
fn gipa_verify_tipp_mipp<E: Pairing>(
    proof: &AggregateProof<E>,
    r_shift: &E::ScalarField,
    transcript: &mut OnchainTranscript,
) -> (
    GipaTUZ<E>,
    E::ScalarField,
    Vec<E::ScalarField>,
    Vec<E::ScalarField>,
) {
    // COM(A,B) = PROD e(A,B) given by prover
    let comms_ab = &proof.tmipp.gipa.comms_ab;
    // COM(C,r) = SUM C^r given by prover
    let comms_c = &proof.tmipp.gipa.comms_c;
    // Z vectors coming from the GIPA proofs
    let zs_ab = &proof.tmipp.gipa.z_ab;
    let zs_c = &proof.tmipp.gipa.z_c;

    // output of the pair commitment T and U in TIPP -> COM((v,w),A,B)
    //let comab2 = proof.com_ab.clone();
    //let Output(t_ab, u_ab) = (comab2.0, comab2.1);
    let Output { 0: t_ab, 1: u_ab } = proof.com_ab.clone();
    let z_ab = proof.ip_ab; // in the end must be equal to Z = A^r * B

    // COM(v,C)
    //let comc2 = proof.com_c.clone();
    //let (t_c, u_c) = (comc2.0, comc2.1);
    let Output { 0: t_c, 1: u_c } = proof.com_c.clone();
    let z_c = proof.agg_c.into_group(); // in the end must be equal to Z = C^r

    let mut final_res = GipaTUZ {
        tab: t_ab,
        uab: u_ab,
        zab: z_ab,
        tc: t_c,
        uc: u_c,
        zc: z_c,
    };

    transcript.append_scalar(&proof.ip_ab);
    transcript.append_point(&proof.agg_c);

    let mut c_inv = transcript.get_challenge::<E::ScalarField>();
    let mut c = c_inv.inverse().unwrap();

    let mut challenges = Vec::new();
    let mut challenges_inv = Vec::new();

    for (((comm_ab, comm_c), z_ab), z_c) in comms_ab
        .iter()
        .zip(comms_c.iter())
        .zip(zs_ab.iter())
        .zip(zs_c.iter())
    {
        // T and U values for right and left for AB part
        let (Output { 0: tab_l, 1: uab_l }, Output { 0: tab_r, 1: uab_r }) = comm_ab;
        let (zab_l, zab_r) = z_ab;
        // T and U values for right and left for C part
        let (Output { 0: tc_l, 1: uc_l }, Output { 0: tc_r, 1: uc_r }) = comm_c;
        let (zc_l, zc_r) = z_c;

        // calc c * c_inv
        if challenges.is_empty() {
            challenges.push(c);
            challenges_inv.push(c_inv);
        } else {
            transcript.append_scalar(&c_inv);

            transcript.append_scalar(tab_l);
            transcript.append_scalar(uab_l);
            transcript.append_scalar(tab_r);
            transcript.append_scalar(uab_r);

            transcript.append_scalar(tc_l);
            transcript.append_scalar(uc_l);
            transcript.append_scalar(tc_r);
            transcript.append_scalar(uc_r);

            transcript.append_scalar(zab_l);
            transcript.append_scalar(zab_r);

            transcript.append_point(zc_l);
            transcript.append_point(zc_r);

            c_inv = transcript.get_challenge::<E::ScalarField>();
            c = c_inv.inverse().unwrap();

            challenges.push(c);
            challenges_inv.push(c_inv);
        }

        let c_repr = c.into_bigint();
        let c_inv_repr = c_inv.into_bigint();

        // we multiple left side by x and right side by x^-1
        let mut res = GipaTUZ::<E>::default();
        // TAB
        res.tab.mul_assign(&tab_l.pow(c_repr));
        res.tab.mul_assign(&tab_r.pow(c_inv_repr));

        // UAB
        res.uab.mul_assign(&uab_l.pow(c_repr));
        res.uab.mul_assign(&uab_r.pow(c_inv_repr));

        // ZAB
        res.zab.mul_assign(&zab_l.pow(c_repr));
        res.zab.mul_assign(&zab_r.pow(c_inv_repr));

        // TC
        res.tc.mul_assign(&tc_l.pow(c_repr));
        res.tc.mul_assign(&tc_r.pow(c_inv_repr));

        // UC
        res.uc.mul_assign(&uc_l.pow(c_repr));
        res.uc.mul_assign(&uc_r.pow(c_inv_repr));

        // ZC
        res.zc.add_assign(&zc_l.mul(c));
        res.zc.add_assign(&zc_r.mul(c_inv));

        final_res.merge(&res);
    }

    // we reverse the order because the polynomial evaluation routine expects
    // the challenges in reverse order.Doing it here allows us to compute the final_r
    // in log time. Challenges are used as well in the KZG verification checks.
    challenges.reverse();
    challenges_inv.reverse();

    let final_r = polynomial_evaluation_product_form_from_transcript(
        &challenges_inv,
        r_shift,
        &E::ScalarField::one(),
    );

    (final_res, final_r, challenges, challenges_inv)
}

/// verify_kzg_opening_g2 takes a KZG opening, the final commitment key, SRS and
/// any shift (in TIPP we shift the v commitment by r^-1) and returns a pairing
/// tuple to check if the opening is correct or not.
pub fn verify_kzg_v<E: Pairing, R: Rng>(
    v_srs: &VerifierSRS<E>,
    final_vkey: &(E::G2Affine, E::G2Affine),
    vkey_opening: &KZGOpening<E::G2Affine>,
    challenges: &[E::ScalarField],
    kzg_challenge: &E::ScalarField,
    acc: &mut PairingCheck<E, R>,
) {
    // f_v(z)
    let vpoly_eval_z = polynomial_evaluation_product_form_from_transcript(
        challenges,
        kzg_challenge,
        &E::ScalarField::one(),
    );
    // -g such that when we test a pairing equation we only need to check if
    // it's equal 1 at the end:
    // e(a,b) = e(c,d) <=> e(a,b)e(-c,d) = 1
    let mut ng = v_srs.g.clone();
    // e(A,B) = e(C,D) <=> e(A,B)e(-C,D) == 1 <=> e(A,B)e(C,D)^-1 == 1
    ng = ng.neg();
    let ng = ng.into_affine();

    // e(g, C_f * h^{-y}) == e(v1 * g^{-x}, \pi) = 1
    kzg_check_v(
        v_srs,
        ng,
        *kzg_challenge,
        vpoly_eval_z,
        final_vkey.0.into_group(),
        v_srs.g_alpha,
        vkey_opening.0,
        acc,
    );

    // e(g, C_f * h^{-y}) == e(v2 * g^{-x}, \pi) = 1
    kzg_check_v(
        v_srs,
        ng,
        *kzg_challenge,
        vpoly_eval_z,
        final_vkey.1.into_group(),
        v_srs.g_beta,
        vkey_opening.1,
        acc,
    );
}

fn kzg_check_v<E: Pairing, R: Rng>(
    v_srs: &VerifierSRS<E>,
    ng: E::G1Affine,
    x: E::ScalarField,
    y: E::ScalarField,
    cf: E::G2,
    vk: E::G1,
    pi: E::G2Affine,
    acc: &mut PairingCheck<E, R>,
) {
    // KZG Check: e(g, C_f * h^{-y}) = e(vk * g^{-x}, \pi)
    // Transformed, such that
    // e(-g, C_f * h^{-y}) * e(vk * g^{-x}, \pi) = 1

    // C_f - (y * h)
    let b = sub!(cf, &mul!(v_srs.h, y)).into_affine();

    // vk - (g * x)
    let c = sub!(vk, &mul!(v_srs.g, x)).into_affine();
    acc.rand(&[(&ng, &b), (&c, &pi)], &E::TargetField::one());
}

/// Similar to verify_kzg_opening_g2 but for g1.
pub fn verify_kzg_w<E: Pairing, R: Rng>(
    v_srs: &VerifierSRS<E>,
    final_wkey: &(E::G1Affine, E::G1Affine),
    wkey_opening: &KZGOpening<E::G1Affine>,
    challenges: &[E::ScalarField],
    r_shift: &E::ScalarField,
    kzg_challenge: &E::ScalarField,
    acc: &mut PairingCheck<E, R>,
) {
    // compute in parallel f(z) and z^n and then combines into f_w(z) = z^n * f(z)
    let fz = polynomial_evaluation_product_form_from_transcript(challenges, kzg_challenge, r_shift);
    let zn = kzg_challenge.pow(&[v_srs.n as u64]);

    let mut fwz = fz;
    fwz.mul_assign(&zn);

    let mut nh = v_srs.h;
    nh = nh.neg();
    let nh = nh.into_affine();

    // e(C_f * g^{-y}, h) = e(\pi, w1 * h^{-x})
    kzg_check_w::<E, R>(
        v_srs,
        nh,
        *kzg_challenge,
        fwz,
        final_wkey.0.into_group(),
        v_srs.h_alpha,
        wkey_opening.0,
        acc,
    );

    // e(C_f * g^{-y}, h) = e(\pi, w2 * h^{-x})
    kzg_check_w::<E, R>(
        v_srs,
        nh,
        *kzg_challenge,
        fwz,
        final_wkey.1.into_group(),
        v_srs.h_beta,
        wkey_opening.1,
        acc,
    );
}

fn kzg_check_w<E: Pairing, R: Rng>(
    v_srs: &VerifierSRS<E>,
    nh: E::G2Affine,
    x: E::ScalarField,
    y: E::ScalarField,
    cf: E::G1,
    wk: E::G2,
    pi: E::G1Affine,
    acc: &mut PairingCheck<E, R>,
) {
    // KZG Check: e(C_f * g^{-y}, h) = e(\pi, wk * h^{-x})
    // Transformed, such that
    // e(C_f * g^{-y}, -h) * e(\pi, wk * h^{-x}) = 1

    // C_f - (y * g)
    let a = sub!(cf, &mul!(v_srs.g, y)).into_affine();

    // wk - (x * h)
    let d = sub!(wk, &mul!(v_srs.h, x)).into_affine();
    acc.rand(&[(&a, &nh), (&pi, &d)], &E::TargetField::one());
}

/// Keeps track of the variables that have been sent by the prover and must
/// be multiplied together by the verifier. Both MIPP and TIPP are merged
/// together.
struct GipaTUZ<E: Pairing> {
    pub tab: E::TargetField,
    pub uab: E::TargetField,
    pub zab: E::TargetField,
    pub tc: E::TargetField,
    pub uc: E::TargetField,
    pub zc: E::G1,
}

impl<E: Pairing> Default for GipaTUZ<E> {
    fn default() -> Self {
        Self {
            tab: E::TargetField::one(),
            uab: E::TargetField::one(),
            zab: E::TargetField::one(),
            tc: E::TargetField::one(),
            uc: E::TargetField::one(),
            zc: E::G1::zero(),
        }
    }
}

impl<E: Pairing> GipaTUZ<E> {
    fn merge(&mut self, other: &Self) {
        self.tab.mul_assign(&other.tab);
        self.uab.mul_assign(&other.uab);
        self.zab.mul_assign(&other.zab);
        self.tc.mul_assign(&other.tc);
        self.uc.mul_assign(&other.uc);
        self.zc.add_assign(&other.zc);
    }
}
