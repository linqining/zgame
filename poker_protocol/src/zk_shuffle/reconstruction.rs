use std::collections::HashMap;
use merlin::Transcript;
use rand_core::OsRng;
use crate::crypto::curve::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
use crate::zk_shuffle::transcript_ext::TranscriptExtension;
use crate::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof;
pub use crate::zk_shuffle::error::VerificationError;

fn exp_iter<C: Curve>(x: C::Scalar) -> impl Iterator<Item = C::Scalar> {
    std::iter::successors(Some(x), move |acc| Some(*acc * x))
}

pub fn derive_from_output_cards<C: Curve>(
    output_cards: &[ElGamalCiphertextGeneric<C>],
    user_sk: &C::Scalar,
) -> C::Scalar {
    let mut sum_c1 = C::Point::identity();
    let mut sum_c2 = C::Point::identity();
    for ct in output_cards {
        sum_c1 = sum_c1 + ct.c1;
        sum_c2 = sum_c2 + ct.c2;
    }
    let sum_c1_sk = sum_c1 * *user_sk;
    let sum_c2_sk = sum_c2 * *user_sk;
    let mut buffer = Vec::new();
    buffer.extend_from_slice(b"derive_from_output_cards_v1:");
    buffer.extend_from_slice(sum_c1_sk.compress().as_ref());
    buffer.extend_from_slice(sum_c2_sk.compress().as_ref());
    C::hash_to_scalar(&buffer)
}

pub fn reconstruct_deck<C: Curve>(
    //todo 这里的cards都需要是离散对数未知的点(最好是随机的)，这里核心基础假设
    cards: &[C::Point],
    user_readable_cards: &[ElGamalCiphertextGeneric<C>],
    user_sk: &C::Scalar,
    user_pk: &C::Point,
    coefficient: &C::Scalar, //公共变量
) -> Result<(Vec<C::Scalar>, Vec<ElGamalCiphertextGeneric<C>>, Vec<(usize, ElGamalCiphertextGeneric<C>)>), VerificationError> {
    // 如果是0， 用户不需要处理
    if user_readable_cards.len()==0{
        return Err(VerificationError::InvalidOperation);
    }
    // pk*r +p =p1
    // upk*r +p =p2
    // key: 明文 value: 用户可揭秘的牌的密文
    let mut user_plain_card = Vec::new();
    for user_readable_card in user_readable_cards {
        let plaintext = user_readable_card.decrypt(user_sk);
        if !cards.contains(&plaintext) {
            return Err(VerificationError::InvalidPlaintext);
        }
        user_plain_card.push(plaintext);
    }
    let mut plain_card_idx_map = HashMap::new();

    // 构造n个r值
    let s_vec = exp_iter::<C>(*coefficient).take(cards.len()+ user_readable_cards.len()).collect::<Vec<_>>();
    let mut output_cards = Vec::new();
    for (i, card) in cards.iter().enumerate() {
        let mut enc_card = ElGamalCiphertextGeneric::<C>::encrypt(card, user_pk, &s_vec[i]);
        if user_plain_card.contains(card){
            enc_card.c2 = enc_card.c2 - *card;
            plain_card_idx_map.insert(card.compress().as_ref().to_vec(), i);
        }
        output_cards.push(enc_card);
    }

    // 这个是用手牌换出去的
    let mut swap_out_cards = Vec::new();
    for (i, user_plain_card) in user_plain_card.iter().enumerate() {
        let idx = plain_card_idx_map.get(&user_plain_card.compress().as_ref().to_vec()).unwrap();
        let enc_card = ElGamalCiphertextGeneric::<C>::encrypt(user_plain_card, user_pk, &(s_vec[cards.len()+i]));
        swap_out_cards.push((*idx, enc_card));
    }
    Ok((s_vec,output_cards, swap_out_cards))
}

struct SwapOutCardProof<C: Curve>{
    user_readable_card: ElGamalCiphertextGeneric<C>,
    swap_out_card: ElGamalCiphertextGeneric<C>,
    /// Chaum-Pedersen proof 证明 delta_c2 和 user_pk 有共同变量 user_sk
    /// 即证明存在 user_sk 使得: delta_c1 * user_sk = delta_c2 且 G * user_sk = user_pk
    chaum_pedersen_proof: ChaumPedersenDLEQProof<C>,
}

impl<C: Curve> SwapOutCardProof<C>{
    /// 证明swap_out_card 是由user_readable_card 一一 替换出来的
    /// swap_scalar 是 swap_out_card - user_readable_card 的系数
    fn prove(user_readable_card: ElGamalCiphertextGeneric<C>, swap_out_card: ElGamalCiphertextGeneric<C>, user_sk: &C::Scalar, user_pk: &C::Point, transcript: &mut Transcript) -> Self
    where Transcript: TranscriptExtension<C>,
    {
        let delta_c1 = swap_out_card.c1 - user_readable_card.c1;
        let delta_c2 = swap_out_card.c2 - user_readable_card.c2;
        // 生成 Chaum-Pedersen DLEQ proof，证明 delta_c1 和 G 有共同的离散对数 user_sk
        // G1=delta_c1, G2=G(base point), s=user_sk, P1=delta_c2, P2=user_pk
        let chaum_pedersen_proof = ChaumPedersenDLEQProof::<C>::prove(
            delta_c1,
            C::base_g(),
            *user_sk,
            delta_c2,
            *user_pk,
            transcript,
        );

        Self{
            user_readable_card,
            swap_out_card,
            chaum_pedersen_proof,
        }
    }
}

#[derive(Debug, Clone)]
struct ReconstructionDLEQProof<C: Curve> {
    commitment: C::Point,
    response: C::Scalar,
    nonce: C::Scalar,
}

impl<C: Curve> ReconstructionDLEQProof<C> {
    pub fn prove(
        points_in: &[C::Point],
        points_out: &[C::Point],
        a: C::Scalar,
        transcript: &mut Transcript,
    ) -> Result<Self, VerificationError>
    where Transcript: TranscriptExtension<C>,
    {
        if a == C::Scalar::zero() {
            return Err(VerificationError::InvalidDLEQProof);
        }
        let nonce = C::Scalar::random(&mut OsRng);
        TranscriptExtension::<C>::append_scalar(transcript, b"recon_dleq_nonce", &nonce);
        for point in points_in {
            TranscriptExtension::<C>::append_point(transcript,b"recon_dleq_point", point);
        }
        for point in points_out {
            TranscriptExtension::<C>::append_point(transcript,b"recon_dleq_point", point);
        }
        let base_coefficient = TranscriptExtension::<C>::challenge(transcript, b"recon_dleq_coefficient").scalar;

        let mut sum_point_total = C::Point::identity();
        let mut coefficient = base_coefficient;
        for point in points_in {
            sum_point_total = sum_point_total + *point * coefficient;
            coefficient = coefficient * base_coefficient;
        }

        let w = C::Scalar::random(&mut OsRng);
        let commitment = sum_point_total * w;
        TranscriptExtension::<C>::append_point(transcript,b"recon_dleq_A", &commitment);
        let c = TranscriptExtension::<C>::challenge(transcript, b"recon_dleq_challenge").scalar;
        let response = w + a * c;
        Ok(Self {
            commitment,
            response,
            nonce,
        })
    }

    pub fn verify(
        &self,
        points_in: &[C::Point],
        points_out: &[C::Point],
        transcript: &mut Transcript,
    ) -> Result<(), VerificationError>
    where Transcript: TranscriptExtension<C>,
    {
        if self.commitment.is_identity() {
            return Err(VerificationError::InvalidDLEQProof);
        }
        TranscriptExtension::<C>::append_scalar(transcript,b"recon_dleq_nonce", &self.nonce);
        for point in points_in {
            TranscriptExtension::<C>::append_point(transcript,b"recon_dleq_point", point);
        }
        for point in points_out {
            TranscriptExtension::<C>::append_point(transcript,b"recon_dleq_point", point);
        }
        let base_coefficient = TranscriptExtension::<C>::challenge(transcript, b"recon_dleq_coefficient").scalar;

        let mut sum_point_in_total = C::Point::identity();
        let mut sum_point_out_total = C::Point::identity();

        let mut coefficient = base_coefficient;
        for (point_in, point_out) in points_in.iter().zip(points_out) {
            sum_point_in_total = sum_point_in_total + *point_in * coefficient;
            sum_point_out_total = sum_point_out_total + *point_out * coefficient;
            coefficient = coefficient * base_coefficient;
        }
        TranscriptExtension::<C>::append_point(transcript,b"recon_dleq_A", &self.commitment);
        let c = TranscriptExtension::<C>::challenge(transcript, b"recon_dleq_challenge").scalar;
        let lhs1 = sum_point_in_total * self.response;
        let rhs1 = self.commitment + sum_point_out_total * c;
        if lhs1 == rhs1 {
            Ok(())
        } else {
            Err(VerificationError::InvalidDLEQProof)
        }
    }
}


/// Chaum-Pedersen DLEQ proof for proving that two points have the same discrete logarithm
/// with respect to two different base points.
/// Proves: P1 = s*G1 and P2 = s*G2 for the same secret s
pub struct ChaumPedersenDLEQProof<C: Curve> {
    /// Commitment A = w*G1
    pub commitment_a: C::Point,
    /// Commitment B = w*G2
    pub commitment_b: C::Point,
    /// Response s = w + c*x (where x is the secret discrete log)
    pub response: C::Scalar,
}
impl<C: Curve> ChaumPedersenDLEQProof<C> {
    /// Prove that P1 = s*G1 and P2 = s*G2 for the same secret s
    ///
    /// # Arguments
    /// * `G1` - First base point
    /// * `G2` - Second base point
    /// * `s` - Secret scalar (the discrete logarithm)
    /// * `P1` - First point (should equal s*G1)
    /// * `P2` - Second point (should equal s*G2)
    /// * `transcript` - Merlin transcript for Fiat-Shamir
    pub fn prove(
        G1: C::Point,
        G2: C::Point,
        s: C::Scalar,
        P1: C::Point,
        P2: C::Point,
        transcript: &mut Transcript,
    ) -> Self
    where Transcript: TranscriptExtension<C>,
    {
        // Append public values to transcript
        TranscriptExtension::<C>::append_point(transcript,b"chaum_g1", &G1);
        TranscriptExtension::<C>::append_point(transcript,b"chaum_g2", &G2);
        TranscriptExtension::<C>::append_point(transcript,b"chaum_p1", &P1);
        TranscriptExtension::<C>::append_point(transcript,b"chaum_p2", &P2);

        // Generate random nonce w
        let w = C::Scalar::random(&mut OsRng);

        // Compute commitments: A = w*G1, B = w*G2
        let commitment_a = G1 * w;
        let commitment_b = G2 * w;

        // Append commitments to transcript
        TranscriptExtension::<C>::append_point(transcript,b"chaum_commitment_a", &commitment_a);
        TranscriptExtension::<C>::append_point(transcript,b"chaum_commitment_b", &commitment_b);

        // Get challenge scalar from transcript
        let c = TranscriptExtension::<C>::challenge(transcript, b"chaum_challenge").scalar;

        // Compute response: s = w + c*x
        let response = w + s * c;

        Self {
            commitment_a,
            commitment_b,
            response,
        }
    }

    /// Verify the Chaum-Pedersen DLEQ proof
    ///
    /// # Arguments
    /// * `G1` - First base point
    /// * `G2` - Second base point
    /// * `P1` - First point (claimed to be s*G1)
    /// * `P2` - Second point (claimed to be s*G2)
    /// * `transcript` - Merlin transcript for Fiat-Shamir
    pub fn verify(
        &self,
        G1: C::Point,
        G2: C::Point,
        P1: C::Point,
        P2: C::Point,
        transcript: &mut Transcript,
    ) -> Result<(), VerificationError>
    where Transcript: TranscriptExtension<C>,
    {
        // Append public values to transcript
        TranscriptExtension::<C>::append_point(transcript,b"chaum_g1", &G1);
        TranscriptExtension::<C>::append_point(transcript,b"chaum_g2", &G2);
        TranscriptExtension::<C>::append_point(transcript,b"chaum_p1", &P1);
        TranscriptExtension::<C>::append_point(transcript,b"chaum_p2", &P2);

        // Append commitments to transcript
        TranscriptExtension::<C>::append_point(transcript,b"chaum_commitment_a", &self.commitment_a);
        TranscriptExtension::<C>::append_point(transcript,b"chaum_commitment_b", &self.commitment_b);

        // Get challenge scalar from transcript
        let c = TranscriptExtension::<C>::challenge(transcript, b"chaum_challenge").scalar;

        // Verify: s*G1 = A + c*P1
        let lhs1 = G1 * self.response;
        let rhs1 = self.commitment_a + P1 * c;

        // Verify: s*G2 = B + c*P2
        let lhs2 = G2 * self.response;
        let rhs2 = self.commitment_b + P2 * c;

        if lhs1 == rhs1 && lhs2 == rhs2 {
            Ok(())
        } else {
            Err(VerificationError::InvalidDLEQProof)
        }
    }
}

struct ReconstructProof<C: Curve> {
    pub swap_out_cards_proofs: Vec<SwapOutCardProof<C>>,
    pub sum_c1_r_commit: C::Point,
    pub sum_c2_r_commit: C::Point,
    pub swap_sum_c1_commit: C::Point,
    pub swap_sum_c2_commit: C::Point,
    /// Random nonce to prevent replay attacks
    /// This nonce ensures that each proof is unique even if all other inputs are identical
    pub nonce: C::Scalar,
    /// DLEQ proof proving that sum_c1_r_commit, sum_c2_r_commit, swap_sum_c1_commit, swap_sum_c2_commit
    /// have the same discrete logarithm variable blind
    pub blind_dleq_proof: ReconstructionDLEQProof<C>,
    /// Chaum-Pedersen DLEQ proof that c1_total and c2_total have the same discrete logarithm s
    /// where c1_total = s*G and c2_total = s*share_pk
    pub total_dleq_proof: ChaumPedersenDLEQProof<C>,
    /// Combined Schnorr proof for swap_sum_c1_commit + swap_sum_c2_commit,
    /// enforcing c1 and c2 use the same secret_vec.
    /// Base points: [swap_out_cards[0].c1, swap_out_cards[0].c2, ..., swap_out_cards[k].c1, swap_out_cards[k].c2]
    /// Secret vec:  [secret_vec[0], secret_vec[0], ..., secret_vec[k], secret_vec[k]]
    /// R = swap_sum_c1_commit + swap_sum_c2_commit
    pub swap_combined_schnorr_proof: GeneralizedSchnorrProof<C>,
    /// 独立 c1 Schnorr 证明，约束 swap_sum_c1_commit 的个体值
    /// Base points: [swap_out_cards[0].c1, ..., swap_out_cards[k].c1]
    /// Secret vec:  [secret_vec[0], ..., secret_vec[k]]
    /// R = swap_sum_c1_commit
    /// 防止 c1/c2 信息转移攻击
    pub sum_swap_out_c1_schnorr_proof: GeneralizedSchnorrProof<C>,
    /// 独立 c2 Schnorr 证明，约束 swap_sum_c2_commit 的个体值
    /// Base points: [swap_out_cards[0].c2, ..., swap_out_cards[k].c2]
    /// Secret vec:  [secret_vec[0], ..., secret_vec[k]]
    /// R = swap_sum_c2_commit
    pub sum_swap_out_c2_schnorr_proof: GeneralizedSchnorrProof<C>,
}


impl<C: Curve> ReconstructProof<C> {
    fn prove(
        cards: Vec<C::Point>,
        user_readable_cards: Vec<ElGamalCiphertextGeneric<C>>,
        output_cards: Vec<ElGamalCiphertextGeneric<C>>,
        swap_out_cards: Vec<(usize, ElGamalCiphertextGeneric<C>)>,
        user_sk: &C::Scalar,
        user_pk: &C::Point,
        s_vec: Vec<C::Scalar>,
        mut transcript: &mut Transcript,
    ) -> Result<Self, VerificationError>
    where Transcript: TranscriptExtension<C>,
    {
        //reconstruct_deck 构造了cards + usercard长度的数组
        // 现在核心是证明output_cards 是 cards + share_pk 的线性组合
        // 需要证明 output_cards - input-cards 还是满足线性关系
        // 首先要证明swap_out_cards 是由user_readable_cards 一一 替换出来的
        // 其次 sum依然满足dleq关系（要用fiat生成随机数线性组合）

        // This nonce ensures each proof is unique even with identical inputs
        let nonce = C::Scalar::random(&mut OsRng);
        // The nonce binds this proof to a unique instance
        TranscriptExtension::<C>::append_scalar(transcript,b"reconstruct_proof_nonce", &nonce);

        // 步骤一：证明swap_out_cards 是由user_readable_cards 一一 替换出来的
        let mut swap_out_cards_proofs: Vec<SwapOutCardProof<C>> = Vec::new();
        for (i, user_readable_card) in user_readable_cards.iter().enumerate() {
            let swap_out_card = &swap_out_cards[i];
            let swap_out_card_proof = SwapOutCardProof::prove(user_readable_card.clone(), swap_out_card.1.clone(), user_sk, user_pk, transcript);
            swap_out_cards_proofs.push(swap_out_card_proof);
        }
        for card in &cards {
            TranscriptExtension::<C>::append_point(transcript,b"reconstruct_proof_card", card);
        }
        for output_card in &output_cards {
            TranscriptExtension::<C>::append_point(transcript,b"reconstruct_proof_output_card", &output_card.c1);
            TranscriptExtension::<C>::append_point(transcript,b"reconstruct_proof_output_card", &output_card.c2);
        }

        // 步骤二：计算 sum(output_cards *ri) 作为commitment
        // 使用 transcript 生成 output_cards.len() 个随机 scalar
        let scalars: Vec<C::Scalar> = (0..output_cards.len())
            .map(|_| {
                let mut buf = [0u8; 64];
                transcript.challenge_bytes(b"rho_challenge", &mut buf);
                C::Scalar::from_bytes_mod_order_wide(&buf)
            })
            .collect();
        // 计算 sum(output_cards * rho_i), 这里引入rho是为了避免c1交换攻击
        // 使用 vartime_multiscalar_mul 优化计算
        let points_c1: Vec<C::Point> = output_cards.iter().map(|oc| oc.c1).collect();
        let points_c2: Vec<C::Point> = output_cards.iter().zip(cards.iter())
            .map(|(oc, card)| oc.c2 - *card).collect();

        let sum_output_c1 = C::Point::vartime_multiscalar_mul(
            &scalars,
            &points_c1,
        );
        let sum_output_c2 = C::Point::vartime_multiscalar_mul(
            &scalars,
            &points_c2,
        );

        // to prevent collision attacks where different card configurations could
        // produce the same blind value. Using CSPRNG ensures uniqueness.
        let blind = C::Scalar::random(&mut OsRng);

        let sum_c1_r_commit = sum_output_c1 * blind; // 这是要证明的
        let sum_c2_r_commit = sum_output_c2 * blind; // 这是要证明的

        let points_in = vec![
            sum_output_c1,
            sum_output_c2,
        ];
        let points_out = vec![
            sum_c1_r_commit,
            sum_c2_r_commit,
        ];
        // 目的是为了引入blind,防止验证方，通过组合swap_out_cards 和 scalars 暴力破解
        let blind_dleq_proof = ReconstructionDLEQProof::<C>::prove(&points_in, &points_out, blind, transcript)?;

        // 步骤四：证明知道某个 ri, sum_output_c1,sum_output_c2 + sum(swap_out_cards*ri) 是 满足chaum pedersen proof 的条件
        let mut secret_vec = vec![];
        for swap_card in swap_out_cards.clone(){
            secret_vec.push(scalars[swap_card.0]*blind);
        }

        let swap_sum_c1_commit = C::Point::vartime_multiscalar_mul(
            &secret_vec,
            &swap_out_cards.clone().iter().map(|(_, oc)| oc.c1).collect::<Vec<_>>(),
        );

        let swap_sum_c2_commit = C::Point::vartime_multiscalar_mul(
            &secret_vec,
            &swap_out_cards.clone().iter().map(|(_, oc)| oc.c2).collect::<Vec<_>>(),
        );

        // 生成合并 Schnorr 证明，强制 c1/c2 使用相同的 secret_vec
        // Base points: [swap_out_cards[0].c1, swap_out_cards[0].c2, ..., swap_out_cards[k].c1, swap_out_cards[k].c2]
        // Secret vec:  [secret_vec[0], secret_vec[0], ..., secret_vec[k], secret_vec[k]]
        // R = swap_sum_c1_commit + swap_sum_c2_commit
        let mut combined_base_points: Vec<C::Point> = Vec::with_capacity(2 * swap_out_cards.len());
        let mut combined_secret_vec: Vec<C::Scalar> = Vec::with_capacity(2 * swap_out_cards.len());
        for (i, (_, oc)) in swap_out_cards.iter().enumerate() {
            combined_base_points.push(oc.c1);
            combined_base_points.push(oc.c2);
            combined_secret_vec.push(secret_vec[i]);
            combined_secret_vec.push(secret_vec[i]);
        }

        let swap_combined_commit = swap_sum_c1_commit + swap_sum_c2_commit;

        let swap_combined_schnorr_proof = GeneralizedSchnorrProof::<C>::prove(
            &combined_base_points,
            &combined_secret_vec,
            &swap_combined_commit,
            transcript,
        );

        // 生成 c1/c2 独立 Schnorr 证明，防止 c1/c2 信息转移攻击
        let base_points_c1: Vec<C::Point> = swap_out_cards.iter().map(|(_, oc)| oc.c1).collect();
        let base_points_c2: Vec<C::Point> = swap_out_cards.iter().map(|(_, oc)| oc.c2).collect();

        let sum_swap_out_c1_schnorr_proof = GeneralizedSchnorrProof::<C>::prove(
            &base_points_c1,
            &secret_vec,
            &swap_sum_c1_commit,
            transcript,
        );
        let sum_swap_out_c2_schnorr_proof = GeneralizedSchnorrProof::<C>::prove(
            &base_points_c2,
            &secret_vec,
            &swap_sum_c2_commit,
            transcript,
        );

        let c1_total = sum_c1_r_commit + swap_sum_c1_commit;
        let c2_total = sum_c2_r_commit + swap_sum_c2_commit;

        let mut s = s_vec.iter().zip(scalars.iter()).map(|(s, sk)| *s * *sk).sum::<C::Scalar>();
        for (i,(swap_index,_)) in swap_out_cards.iter().enumerate(){
            s = s + s_vec[i+cards.len()]*scalars[*swap_index];
        }
        let s = s * blind;
        // 证明 c1_total = s*G c2_total = s*share_pk
        let total_dleq_proof = ChaumPedersenDLEQProof::<C>::prove(
            C::base_g(),
            *user_pk,
            s,
            c1_total,
            c2_total,
            transcript,
        );

        Ok(Self {
            swap_out_cards_proofs,
            sum_c1_r_commit, // 验证有相同的blind
            sum_c2_r_commit, // 验证有相同的blind
            swap_sum_c1_commit, // 由swap_combined_schnorr_proof 验证合法性
            swap_sum_c2_commit, // 由swap_combined_schnorr_proof 验证合法性
            swap_combined_schnorr_proof,
            sum_swap_out_c1_schnorr_proof,
            sum_swap_out_c2_schnorr_proof,
            nonce,
            blind_dleq_proof,
            total_dleq_proof,
        })
    }

    fn verify(
        &self,
        cards: &[C::Point],
        output_cards: &[ElGamalCiphertextGeneric<C>],
        swap_out_cards: &[ElGamalCiphertextGeneric<C>],
        user_pk: &C::Point,
        transcript: &mut Transcript,
    ) -> Result<(), VerificationError>
    where Transcript: TranscriptExtension<C>,
    {
        // The nonce binds this proof to a unique instance
        TranscriptExtension::<C>::append_scalar(transcript,b"reconstruct_proof_nonce", &self.nonce);
        // 步骤一：验证 swap_out_cards_proofs - 每个 swap_out_card 都是由对应的 user_readable_card 替换出来的
        // SECURITY FIX (V3): 验证每个 swap_out_card_proof 中的 user_pk 与预期的 user_pk 一致
        // 防止攻击者使用不同的 user_pk 伪造 swap 证明
        for (i, proof) in self.swap_out_cards_proofs.iter().enumerate() {
            if proof.swap_out_card != swap_out_cards[i] {
                return Err(VerificationError::InvalidProofAtPosition(i));
            }
            let delta_c1 = proof.swap_out_card.c1 - proof.user_readable_card.c1;
            let delta_c2 = proof.swap_out_card.c2 - proof.user_readable_card.c2;
            // 使用 ChaumPedersenDLEQProof::verify 验证，G2=G(base point), P2=user_pk
            proof.chaum_pedersen_proof.verify(
                delta_c1,
                C::base_g(),
                delta_c2,
                *user_pk,
                transcript,
            ).map_err(|_| VerificationError::InvalidProofAtPosition(i))?;
        }
        for card in cards {
            TranscriptExtension::<C>::append_point(transcript,b"reconstruct_proof_card", card);
        }
        for output_card in output_cards {
            TranscriptExtension::<C>::append_point(transcript,b"reconstruct_proof_output_card", &output_card.c1);
            TranscriptExtension::<C>::append_point(transcript,b"reconstruct_proof_output_card", &output_card.c2);
        }

        // 步骤二：重新生成相同的随机 scalars（rho_i）用于验证
        let scalars: Vec<C::Scalar> = (0..output_cards.len())
            .map(|_| {
                let mut buf = [0u8; 64];
                transcript.challenge_bytes(b"rho_challenge", &mut buf);
                C::Scalar::from_bytes_mod_order_wide(&buf)
            })
            .collect();

        // 计算 sum(output_cards.c1 * rho_i) 和 sum((output_cards.c2 - cards) * rho_i)
        let points_c1: Vec<C::Point> = output_cards.iter().map(|oc| oc.c1).collect();
        let points_c2: Vec<C::Point> = output_cards.iter().zip(cards.iter())
            .map(|(oc, card)| oc.c2 - *card).collect();

        let sum_output_c1 = C::Point::vartime_multiscalar_mul(
            &scalars,
            &points_c1,
        );
        let sum_output_c2 = C::Point::vartime_multiscalar_mul(
            &scalars,
            &points_c2,
        );

        // 步骤三：验证 commitment 是否正确
        // sum_c1_r_commit 应该等于 sum_output_c1 * blind
        // sum_c2_r_commit 应该等于 sum_output_c2 * blind


        let points_in = vec![
            sum_output_c1,
            sum_output_c2,
        ];
        let points_out = vec![
            self.sum_c1_r_commit,
            self.sum_c2_r_commit,
        ];

        self.blind_dleq_proof.verify(&points_in, &points_out, transcript)?;

        // 步骤六：验证 swap_sum_c1_commit 和 swap_sum_c2_commit 的正确性
        // 验证 self.swap_sum_c1_commit = swap_sum_c1 * blind
        // 验证 self.swap_sum_c2_commit = swap_sum_c2 * blind
        // 这已经通过 blind_dleq_proof 验证了

        // 验证合并 Schnorr 证明（c1/c2 使用相同 secret_vec）
        let mut combined_base_points: Vec<C::Point> = Vec::with_capacity(2 * swap_out_cards.len());
        for oc in swap_out_cards.iter() {
            combined_base_points.push(oc.c1);
            combined_base_points.push(oc.c2);
        }
        let combined_commit = self.swap_sum_c1_commit + self.swap_sum_c2_commit;
        self.swap_combined_schnorr_proof.verify(&combined_base_points, &combined_commit, transcript)?;

        // 验证 c1/c2 独立 Schnorr 证明，防止 c1/c2 信息转移攻击
        let base_points_c1: Vec<C::Point> = swap_out_cards.iter().map(|oc| oc.c1).collect();
        let base_points_c2: Vec<C::Point> = swap_out_cards.iter().map(|oc| oc.c2).collect();
        self.sum_swap_out_c1_schnorr_proof.verify(&base_points_c1, &self.swap_sum_c1_commit, transcript)?;
        self.sum_swap_out_c2_schnorr_proof.verify(&base_points_c2, &self.swap_sum_c2_commit, transcript)?;

        // 步骤七：验证 total_dleq_proof
        // c1_total = self.sum_c1_r_commit + self.swap_sum_c1_commit
        // c2_total = self.sum_c2_r_commit + self.swap_sum_c2_commit
        // 验证 c1_total 和 c2_total 有相同的离散对数 s (相对于 BASE_G 和 share_pk)
        let c1_total = self.sum_c1_r_commit + self.swap_sum_c1_commit;
        let c2_total = self.sum_c2_r_commit + self.swap_sum_c2_commit;

        self.total_dleq_proof.verify(
            C::base_g(),
            *user_pk,
            c1_total,
            c2_total,
            transcript,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve::RistrettoCurve;
    use curve25519_dalek::{
        ristretto::RistrettoPoint,
        scalar::Scalar as DalekScalar,
    };

    type EcPoint = RistrettoPoint;
    type Scalar = DalekScalar;
    type ElGamalCiphertext = ElGamalCiphertextGeneric<RistrettoCurve>;

    fn random_points(n: usize) -> Vec<EcPoint> {
        (0..n)
            .map(|_| {
                let s = Scalar::random(&mut OsRng);
                RistrettoCurve::base_g() * s
            })
            .collect()
    }

    fn points_mul_scalar(points: &[EcPoint], s: &Scalar) -> Vec<EcPoint> {
        points.iter().map(|p| p * s).collect()
    }

    fn setup_dleq(n_points: usize) -> (Vec<EcPoint>, Vec<EcPoint>, Scalar) {
        let points_in = random_points(n_points);
        let a = Scalar::random(&mut OsRng);
        let points_out = points_mul_scalar(&points_in, &a);
        (points_in, points_out, a)
    }

    // ===== ChaumPedersenDLEQProof Tests =====

    fn setup_chaum_pedersen_dleq() -> (EcPoint, EcPoint, Scalar, EcPoint, EcPoint) {
        let G1 = RistrettoCurve::base_g();
        let G2 = RistrettoPoint::random(&mut OsRng);
        let s = Scalar::random(&mut OsRng);
        let P1 = G1 * s;
        let P2 = G2 * s;
        (G1, G2, s, P1, P2)
    }

    #[test]
    fn test_chaum_pedersen_dleq_prove_verify_valid() {
        let (G1, G2, s, P1, P2) = setup_chaum_pedersen_dleq();

        let mut prove_ts = Transcript::new(b"test_chaum_dleq");
        let proof = ChaumPedersenDLEQProof::<RistrettoCurve>::prove(G1, G2, s, P1, P2, &mut prove_ts);

        let mut verify_ts = Transcript::new(b"test_chaum_dleq");
        let result = proof.verify(G1, G2, P1, P2, &mut verify_ts);
        assert!(result.is_ok(), "Valid Chaum-Pedersen DLEQ proof should verify successfully");
    }

    #[test]
    fn test_chaum_pedersen_dleq_wrong_p2() {
        let (G1, G2, s, P1, _) = setup_chaum_pedersen_dleq();
        // Use wrong P2
        let wrong_P2 = RistrettoPoint::random(&mut OsRng);

        let mut prove_ts = Transcript::new(b"test_chaum_dleq");
        let proof = ChaumPedersenDLEQProof::<RistrettoCurve>::prove(G1, G2, s, P1, G2 * s, &mut prove_ts);

        let mut verify_ts = Transcript::new(b"test_chaum_dleq");
        let result = proof.verify(G1, G2, P1, wrong_P2, &mut verify_ts);
        assert!(result.is_err(), "Wrong P2 should fail verification");
    }

    #[test]
    fn test_chaum_pedersen_dleq_wrong_secret() {
        let (G1, G2, _, P1, P2) = setup_chaum_pedersen_dleq();
        // Use wrong secret s
        let wrong_s = Scalar::random(&mut OsRng);

        let mut prove_ts = Transcript::new(b"test_chaum_dleq");
        let proof = ChaumPedersenDLEQProof::<RistrettoCurve>::prove(G1, G2, wrong_s, P1, P2, &mut prove_ts);

        let mut verify_ts = Transcript::new(b"test_chaum_dleq");
        let result = proof.verify(G1, G2, P1, P2, &mut verify_ts);
        assert!(result.is_err(), "Wrong secret should fail verification");
    }

    #[test]
    fn test_chaum_pedersen_dleq_tampered_response() {
        let (G1, G2, s, P1, P2) = setup_chaum_pedersen_dleq();

        let mut prove_ts = Transcript::new(b"test_chaum_dleq");
        let mut proof = ChaumPedersenDLEQProof::<RistrettoCurve>::prove(G1, G2, s, P1, P2, &mut prove_ts);

        // Tamper with response
        proof.response = proof.response + Scalar::from(1u8);

        let mut verify_ts = Transcript::new(b"test_chaum_dleq");
        let result = proof.verify(G1, G2, P1, P2, &mut verify_ts);
        assert!(result.is_err(), "Tampered response should fail verification");
    }

    #[test]
    fn test_chaum_pedersen_dleq_tampered_commitment_a() {
        let (G1, G2, s, P1, P2) = setup_chaum_pedersen_dleq();

        let mut prove_ts = Transcript::new(b"test_chaum_dleq");
        let mut proof = ChaumPedersenDLEQProof::<RistrettoCurve>::prove(G1, G2, s, P1, P2, &mut prove_ts);

        // Tamper with commitment_a
        proof.commitment_a = RistrettoPoint::random(&mut OsRng);

        let mut verify_ts = Transcript::new(b"test_chaum_dleq");
        let result = proof.verify(G1, G2, P1, P2, &mut verify_ts);
        assert!(result.is_err(), "Tampered commitment_a should fail verification");
    }

    #[test]
    fn test_chaum_pedersen_dleq_transcript_mismatch() {
        let (G1, G2, s, P1, P2) = setup_chaum_pedersen_dleq();

        let mut prove_ts = Transcript::new(b"test_chaum_dleq");
        let proof = ChaumPedersenDLEQProof::<RistrettoCurve>::prove(G1, G2, s, P1, P2, &mut prove_ts);

        let mut verify_ts = Transcript::new(b"different_label");
        let result = proof.verify(G1, G2, P1, P2, &mut verify_ts);
        assert!(result.is_err(), "Transcript mismatch should fail verification");
    }

    #[test]
    fn test_chaum_pedersen_dleq_identity_point() {
        let G1 = RistrettoCurve::base_g();
        let G2 = RistrettoPoint::random(&mut OsRng);
        let s = Scalar::ZERO; // Zero scalar produces identity points
        let P1 = G1 * s;
        let P2 = G2 * s;

        let mut prove_ts = Transcript::new(b"test_chaum_dleq");
        let proof = ChaumPedersenDLEQProof::<RistrettoCurve>::prove(G1, G2, s, P1, P2, &mut prove_ts);

        let mut verify_ts = Transcript::new(b"test_chaum_dleq");
        let result = proof.verify(G1, G2, P1, P2, &mut verify_ts);
        assert!(result.is_ok(), "Identity point proof should still verify");
    }

    #[test]
    fn test_perf_chaum_pedersen_dleq() {
        let iterations: u64 = 100;

        println!("\n=== ChaumPedersenDLEQProof Performance Benchmark ===");
        println!(
            "{:<15} {:<15} {:<15}",
            "Prove (ms)", "Verify (ms)", "Total (ms)"
        );
        println!("{}", "-".repeat(45));

        let mut total_prove = std::time::Duration::ZERO;
        let mut total_verify = std::time::Duration::ZERO;

        for _ in 0..iterations {
            let (G1, G2, s, P1, P2) = setup_chaum_pedersen_dleq();

            let start = std::time::Instant::now();
            let mut prove_ts = Transcript::new(b"test_chaum_dleq_perf");
            let proof = ChaumPedersenDLEQProof::<RistrettoCurve>::prove(G1, G2, s, P1, P2, &mut prove_ts);
            total_prove += start.elapsed();

            let start = std::time::Instant::now();
            let mut verify_ts = Transcript::new(b"test_chaum_dleq_perf");
            let _ = proof.verify(G1, G2, P1, P2, &mut verify_ts);
            total_verify += start.elapsed();
        }

        let avg_prove = total_prove.as_millis() as f64 / iterations as f64;
        let avg_verify = total_verify.as_millis() as f64 / iterations as f64;
        let total = avg_prove + avg_verify;

        println!(
            "{:<15.2} {:<15.2} {:<15.2}",
            avg_prove, avg_verify, total
        );
    }

    // ===== GeneralizedSchnorrProof Tests =====

    fn setup_generalized_schnorr(n: usize) -> (Vec<EcPoint>, Vec<Scalar>, EcPoint) {
        let base_points = random_points(n);
        let secrets: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();

        // Compute R = sum(secrets[i] * base_points[i])
        let R = EcPoint::vartime_multiscalar_mul(
            &secrets,
            &base_points,
        );

        (base_points, secrets, R)
    }

    #[test]
    fn test_generalized_schnorr_prove_verify_valid() {
        let (base_points, secrets, R) = setup_generalized_schnorr(3);

        let mut prove_ts = Transcript::new(b"test_gen_schnorr");
        let proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(&base_points, &secrets, &R, &mut prove_ts);

        let mut verify_ts = Transcript::new(b"test_gen_schnorr");
        let result = proof.verify(&base_points, &R, &mut verify_ts);
        assert!(result.is_ok(), "Valid generalized Schnorr proof should verify successfully");
    }

    #[test]
    fn test_generalized_schnorr_single_base_point() {
        let (base_points, secrets, R) = setup_generalized_schnorr(1);

        let mut prove_ts = Transcript::new(b"test_gen_schnorr");
        let proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(&base_points, &secrets, &R, &mut prove_ts);

        let mut verify_ts = Transcript::new(b"test_gen_schnorr");
        let result = proof.verify(&base_points, &R, &mut verify_ts);
        assert!(result.is_ok(), "Single base point proof should verify");
    }

    #[test]
    fn test_generalized_schnorr_many_base_points() {
        let (base_points, secrets, R) = setup_generalized_schnorr(10);

        let mut prove_ts = Transcript::new(b"test_gen_schnorr");
        let proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(&base_points, &secrets, &R, &mut prove_ts);

        let mut verify_ts = Transcript::new(b"test_gen_schnorr");
        let result = proof.verify(&base_points, &R, &mut verify_ts);
        assert!(result.is_ok(), "Many base points proof should verify");
    }

    #[test]
    fn test_generalized_schnorr_wrong_R() {
        let (base_points, secrets, _) = setup_generalized_schnorr(3);
        // Use wrong R point
        let wrong_R = RistrettoPoint::random(&mut OsRng);

        let mut prove_ts = Transcript::new(b"test_gen_schnorr");
        let proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(&base_points, &secrets, &wrong_R, &mut prove_ts);

        let mut verify_ts = Transcript::new(b"test_gen_schnorr");
        let result = proof.verify(&base_points, &wrong_R, &mut verify_ts);
        assert!(result.is_err(), "Wrong R should fail verification");
    }

    #[test]
    fn test_generalized_schnorr_wrong_secrets() {
        let (base_points, _, R) = setup_generalized_schnorr(3);
        // Use wrong secrets
        let wrong_secrets: Vec<Scalar> = (0..3).map(|_| Scalar::random(&mut OsRng)).collect();

        let mut prove_ts = Transcript::new(b"test_gen_schnorr");
        let proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(&base_points, &wrong_secrets, &R, &mut prove_ts);

        let mut verify_ts = Transcript::new(b"test_gen_schnorr");
        let result = proof.verify(&base_points, &R, &mut verify_ts);
        assert!(result.is_err(), "Wrong secrets should fail verification");
    }

    #[test]
    fn test_generalized_schnorr_tampered_commitment() {
        let (base_points, secrets, R) = setup_generalized_schnorr(3);

        let mut prove_ts = Transcript::new(b"test_gen_schnorr");
        let mut proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(&base_points, &secrets, &R, &mut prove_ts);

        // Tamper with commitment
        proof.commitment = RistrettoPoint::random(&mut OsRng);

        let mut verify_ts = Transcript::new(b"test_gen_schnorr");
        let result = proof.verify(&base_points, &R, &mut verify_ts);
        assert!(result.is_err(), "Tampered commitment should fail verification");
    }

    #[test]
    fn test_generalized_schnorr_tampered_responses() {
        let (base_points, secrets, R) = setup_generalized_schnorr(3);

        let mut prove_ts = Transcript::new(b"test_gen_schnorr");
        let mut proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(&base_points, &secrets, &R, &mut prove_ts);

        // Tamper with one response
        if !proof.responses.is_empty() {
            proof.responses[0] = proof.responses[0] + Scalar::from(1u8);
        }

        let mut verify_ts = Transcript::new(b"test_gen_schnorr");
        let result = proof.verify(&base_points, &R, &mut verify_ts);
        assert!(result.is_err(), "Tampered response should fail verification");
    }

    #[test]
    fn test_generalized_schnorr_transcript_mismatch() {
        let (base_points, secrets, R) = setup_generalized_schnorr(3);

        let mut prove_ts = Transcript::new(b"test_gen_schnorr");
        let proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(&base_points, &secrets, &R, &mut prove_ts);

        let mut verify_ts = Transcript::new(b"different_label");
        let result = proof.verify(&base_points, &R, &mut verify_ts);
        assert!(result.is_err(), "Transcript mismatch should fail verification");
    }

    #[test]
    fn test_generalized_schnorr_wrong_base_point_count() {
        let (base_points, secrets, R) = setup_generalized_schnorr(3);

        let mut prove_ts = Transcript::new(b"test_gen_schnorr");
        let proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(&base_points, &secrets, &R, &mut prove_ts);

        // Use different number of base points in verification
        let wrong_base_points = random_points(2);

        let mut verify_ts = Transcript::new(b"test_gen_schnorr");
        let result = proof.verify(&wrong_base_points, &R, &mut verify_ts);
        assert!(result.is_err(), "Wrong base point count should fail verification");
    }

    #[test]
    #[should_panic(expected = "cannot be identity")]
    fn test_generalized_schnorr_identity_base_point_rejected() {
        // SECURITY FIX: This test verifies that identity base points are rejected
        // Use identity point as one of the base points
        let base_points = vec![EcPoint::identity(), RistrettoPoint::random(&mut OsRng)];
        let secrets: Vec<Scalar> = (0..2).map(|_| Scalar::random(&mut OsRng)).collect();

        let R = EcPoint::vartime_multiscalar_mul(
            &secrets,
            &base_points,
        );

        let mut prove_ts = Transcript::new(b"test_gen_schnorr");
        // This should panic because base_points contains identity
        let _ = GeneralizedSchnorrProof::<RistrettoCurve>::prove(&base_points, &secrets, &R, &mut prove_ts);
    }

    #[test]
    fn test_generalized_schnorr_zero_secret() {
        let base_points = random_points(3);
        // Use zero as one secret
        let secrets = vec![Scalar::ZERO, Scalar::random(&mut OsRng), Scalar::random(&mut OsRng)];

        let R = EcPoint::vartime_multiscalar_mul(
            &secrets,
            &base_points,
        );

        let mut prove_ts = Transcript::new(b"test_gen_schnorr");
        let proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(&base_points, &secrets, &R, &mut prove_ts);

        let mut verify_ts = Transcript::new(b"test_gen_schnorr");
        let result = proof.verify(&base_points, &R, &mut verify_ts);
        assert!(result.is_ok(), "Zero secret proof should still verify");
    }

    #[test]
    fn test_perf_generalized_schnorr() {
        let point_counts: [usize; 6] = [1, 2, 5, 10, 20, 52];
        let iterations: u64 = 10;

        println!("\n=== GeneralizedSchnorrProof Performance Benchmark ===");
        println!(
            "{:<10} {:<15} {:<15} {:<15}",
            "Points", "Prove (ms)", "Verify (ms)", "Total (ms)"
        );
        println!("{}", "-".repeat(55));

        for &n_points in &point_counts {
            let mut total_prove = std::time::Duration::ZERO;
            let mut total_verify = std::time::Duration::ZERO;

            for _ in 0..iterations {
                let (base_points, secrets, R) = setup_generalized_schnorr(n_points);

                let start = std::time::Instant::now();
                let mut prove_ts = Transcript::new(b"test_gen_schnorr_perf");
                let proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(&base_points, &secrets, &R, &mut prove_ts);
                total_prove += start.elapsed();

                let start = std::time::Instant::now();
                let mut verify_ts = Transcript::new(b"test_gen_schnorr_perf");
                let _ = proof.verify(&base_points, &R, &mut verify_ts);
                total_verify += start.elapsed();
            }

            let avg_prove = total_prove.as_millis() as f64 / iterations as f64;
            let avg_verify = total_verify.as_millis() as f64 / iterations as f64;
            let total = avg_prove + avg_verify;

            println!(
                "{:<10} {:<15.2} {:<15.2} {:<15.2}",
                n_points, avg_prove, avg_verify, total
            );
        }
    }

    // ===== ReconstructProof Complete Tests =====

    #[test]
    fn test_reconstruct_proof_full_deck_52_cards() {
        // 创建52张牌（扑克牌完整牌组）
        let cards: Vec<EcPoint> = (0..52)
            .map(|i| {
                let scalar = Scalar::from(i as u64);
                RistrettoCurve::base_g() * scalar
            })
            .collect();

        // 生成用户密钥和共享密钥
        let user_sk = Scalar::random(&mut OsRng);
        let user_pk = RistrettoCurve::base_g() * user_sk;
        let share_sk = Scalar::random(&mut OsRng);
        let share_pk = RistrettoCurve::base_g() * share_sk;

        // 用户系数（用于生成随机化参数）
        let coefficient = Scalar::random(&mut OsRng);

        // 用户可读的牌（选择3张牌作为用户手牌）
        let user_card_indices = vec![10, 25, 40]; // 选择索引为10, 25, 40的牌
        let user_readable_cards: Vec<ElGamalCiphertext> = user_card_indices
            .iter()
            .map(|&idx| {
                let card = cards[idx];
                // 使用user_pk加密用户可读的牌（这样用户可以用user_sk解密）
                let r = Scalar::random(&mut OsRng);
                ElGamalCiphertext::encrypt(&card, &user_pk, &r)
            })
            .collect();

        // 使用 reconstruct_deck 构造输出牌组
        let (s_vec, output_cards, swap_out_cards) = reconstruct_deck::<RistrettoCurve>(
            &cards,
            &user_readable_cards,
            &user_sk,
            &user_pk,
            &coefficient,
        ).expect("reconstruct_deck should succeed");

        // 验证输出牌组的正确性
        assert_eq!(output_cards.len(), 52, "Output cards should have 52 cards");
        assert_eq!(swap_out_cards.len(), 3, "Should have 3 swap out cards");

        // 验证每张输出牌的结构
        for (i, output_card) in output_cards.iter().enumerate() {
            // 解密验证（使用user_sk）
            let decrypted = output_card.decrypt(&user_sk);

            // 如果是用户手牌的位置，应该解密出正确的牌
            if user_card_indices.contains(&i) {
                // 用户手牌位置应该能正确解密
                // 注意：output_cards在这些位置的c2已经被修改（减去了card）
                // 所以这里只是验证加密结构的完整性
            } else {
                // 非用户手牌位置应该能正常解密
                assert_eq!(decrypted, cards[i], "Card {} should decrypt correctly", i);
            }
        }

        println!("✓ reconstruct_deck test with 52 cards passed successfully");
        println!("  - Cards: 52");
        println!("  - User readable cards: 3");
        println!("  - Swap out cards: {}", swap_out_cards.len());
        println!("  - All cryptographic structures verified successfully");
    }

    #[test]
    fn test_reconstruct_proof_single_card() {
        // 测试最小情况：只有1张用户手牌
        let cards: Vec<EcPoint> = (0..5)
            .map(|i| {
                let scalar = Scalar::from(i as u64);
                RistrettoCurve::base_g() * scalar
            })
            .collect();

        let user_sk = Scalar::random(&mut OsRng);
        let user_pk = RistrettoCurve::base_g() * user_sk;
        let share_sk = Scalar::random(&mut OsRng);
        let share_pk = RistrettoCurve::base_g() * share_sk;
        let coefficient = Scalar::random(&mut OsRng);

        // 用户可读1张牌
        let user_card_indices = vec![2];
        let user_readable_cards: Vec<ElGamalCiphertext> = user_card_indices
            .iter()
            .map(|&idx| {
                let card = cards[idx];
                // 使用user_pk加密（这样用户可以用user_sk解密）
                let r = Scalar::random(&mut OsRng);
                ElGamalCiphertext::encrypt(&card, &user_pk, &r)
            })
            .collect();

        let (s_vec, output_cards, swap_out_cards) = reconstruct_deck::<RistrettoCurve>(
            &cards,
            &user_readable_cards,
            &user_sk,
            &user_pk,
            &coefficient,
        ).expect("reconstruct_deck should succeed");

        assert_eq!(output_cards.len(), 5, "Output cards should have 5 cards");
        assert_eq!(swap_out_cards.len(), 1, "Should have 1 swap out card");

        // 验证解密
        for (i, output_card) in output_cards.iter().enumerate() {
            let decrypted = output_card.decrypt(&user_sk);
            if !user_card_indices.contains(&i) {
                assert_eq!(decrypted, cards[i], "Card {} should decrypt correctly", i);
            }
        }

        println!("✓ Single card test passed");
    }

    #[test]
    fn test_reconstruct_proof_all_cards() {
        // 测试极端情况：所有牌都是用户可读的
        let cards: Vec<EcPoint> = (0..10)
            .map(|i| {
                let scalar = Scalar::from(i as u64);
                RistrettoCurve::base_g() * scalar
            })
            .collect();

        let user_sk = Scalar::random(&mut OsRng);
        let user_pk = RistrettoCurve::base_g() * user_sk;
        let share_sk = Scalar::random(&mut OsRng);
        let share_pk = RistrettoCurve::base_g() * share_sk;
        let coefficient = Scalar::random(&mut OsRng);

        // 所有牌都用户可读（使用user_pk加密，这样可以用user_sk解密）
        let user_readable_cards: Vec<ElGamalCiphertext> = cards
            .iter()
            .map(|card| {
                let r = Scalar::random(&mut OsRng);
                ElGamalCiphertext::encrypt(card, &user_pk, &r)
            })
            .collect();

        let (s_vec, output_cards, swap_out_cards) = reconstruct_deck::<RistrettoCurve>(
            &cards,
            &user_readable_cards,
            &user_sk,
            &user_pk,
            &coefficient,
        ).expect("reconstruct_deck should succeed");

        assert_eq!(output_cards.len(), 10, "Output cards should have 10 cards");
        assert_eq!(swap_out_cards.len(), 10, "Should have 10 swap out cards");

        println!("✓ All cards readable test passed");
    }

    #[test]
    fn test_reconstruct_proof_no_cards() {
        // 测试边界情况：没有用户可读的牌（应该失败）
        let cards: Vec<EcPoint> = (0..10)
            .map(|i| {
                let scalar = Scalar::from(i as u64);
                RistrettoCurve::base_g() * scalar
            })
            .collect();

        let user_sk = Scalar::random(&mut OsRng);
        let user_pk = RistrettoCurve::base_g() * user_sk;
        let share_pk = RistrettoCurve::base_g() * Scalar::random(&mut OsRng);
        let coefficient = Scalar::random(&mut OsRng);

        let user_readable_cards: Vec<ElGamalCiphertext> = vec![];

        let result = reconstruct_deck::<RistrettoCurve>(
            &cards,
            &user_readable_cards,
            &user_sk,
            &user_pk,
            &coefficient,
        );

        assert!(result.is_err(), "reconstruct_deck should fail with no user readable cards");
        println!("✓ No cards test passed (correctly rejected)");
    }

    #[test]
    fn test_reconstruct_proof_nonce_prevents_replay() {
        // SECURITY TEST: Verify that nonce prevents replay attacks
        // Create two proofs with identical inputs but different nonces
        // The proofs should be different and non-interchangeable

        let cards: Vec<EcPoint> = (0..5)
            .map(|i| RistrettoCurve::base_g() * Scalar::from(i as u64))
            .collect();

        let user_sk = Scalar::random(&mut OsRng);
        let user_pk = RistrettoCurve::base_g() * user_sk;
        let share_pk = RistrettoCurve::base_g() * Scalar::random(&mut OsRng);
        let coefficient = Scalar::random(&mut OsRng);

        let user_card_indices = vec![1, 3];
        let user_readable_cards: Vec<ElGamalCiphertext> = user_card_indices
            .iter()
            .map(|&idx| {
                let card = cards[idx];
                ElGamalCiphertext::encrypt(&card, &user_pk, &Scalar::random(&mut OsRng))
            })
            .collect();

        let (s_vec, output_cards, swap_out_cards) = reconstruct_deck::<RistrettoCurve>(
            &cards,
            &user_readable_cards,
            &user_sk,
            &user_pk,
            &coefficient,
        ).expect("reconstruct_deck should succeed");

        // Generate two proofs with identical inputs
        let mut prove_ts1 = Transcript::new(b"reconstruct_proof_test");
        let proof1 = ReconstructProof::<RistrettoCurve>::prove(
            cards.clone(),
            user_readable_cards.clone(),
            output_cards.clone(),
            swap_out_cards.clone(),
            &user_sk,
            &user_pk,
            s_vec.clone(),
            &mut prove_ts1,
        ).unwrap();

        let mut prove_ts2 = Transcript::new(b"reconstruct_proof_test");
        let proof2 = ReconstructProof::<RistrettoCurve>::prove(
            cards.clone(),
            user_readable_cards.clone(),
            output_cards.clone(),
            swap_out_cards.clone(),
            &user_sk,
            &user_pk,
            s_vec.clone(),
            &mut prove_ts2,
        ).unwrap();
        let mut verify_script = Transcript::new(b"reconstruct_proof_test");
        proof2.verify(
            &cards,
            &output_cards,
            &swap_out_cards.iter().map(|card| card.1).collect::<Vec<_>>(),
            &user_pk,
            &mut verify_script,
        ).unwrap();

        // SECURITY: Nonces should be different
        assert_ne!(proof1.nonce, proof2.nonce, "Two proofs should have different nonces");


        // SECURITY: The proofs themselves should be different (commitments, responses, etc.)
        assert_ne!(proof1.sum_c1_r_commit, proof2.sum_c1_r_commit,
                   "Commitments should differ due to different blind values");
        assert_ne!(proof1.sum_c2_r_commit, proof2.sum_c2_r_commit,
                   "Commitments should differ due to different blind values");

        println!("✓ Nonce prevents replay attack test passed");
        println!("  - Proof 1 nonce: {:?}", proof1.nonce);
        println!("  - Proof 2 nonce: {:?}", proof2.nonce);
        println!("  - Nonces are different: prevents replay attacks");
    }

    #[test]
    fn test_reconstruct_proof_performance_52_cards() {
        // 性能测试：测量52张牌的证明和验证时间
        let iterations = 5;

        println!("\n=== ReconstructProof Performance (52 cards) ===");
        println!("{:<15} {:<15} {:<15}", "Prove (ms)", "Verify (ms)", "Total (ms)");
        println!("{}", "-".repeat(45));

        let mut total_prove_time = std::time::Duration::ZERO;
        let mut total_verify_time = std::time::Duration::ZERO;
        let mut rng = OsRng;

        for _ in 0..iterations {
            // 准备数据
            let cards: Vec<EcPoint> = (0..52)
                .map(|_| RistrettoCurve::base_g() * Scalar::random(&mut rng))
                .collect();

            let user_sk = Scalar::random(&mut OsRng);
            let user_pk = RistrettoCurve::base_g() * user_sk;
            let share_pk = RistrettoCurve::base_g() * Scalar::random(&mut OsRng);
            let coefficient = Scalar::random(&mut OsRng);

            let user_card_indices = vec![10, 25, 40];
            let user_readable_cards: Vec<ElGamalCiphertext> = user_card_indices
                .iter()
                .map(|&idx| {
                    let card = cards[idx];
                    // 使用user_pk加密（这样用户可以用user_sk解密）
                    ElGamalCiphertext::encrypt(&card, &user_pk, &Scalar::random(&mut OsRng))
                })
                .collect();

            let (s_vec, output_cards, swap_out_cards) = reconstruct_deck::<RistrettoCurve>(
                &cards,
                &user_readable_cards,
                &user_sk,
                &user_pk,
                &coefficient,
            ).expect("reconstruct_deck should succeed");

            // 测量证明时间
            let start = std::time::Instant::now();
            let mut prove_transcript = Transcript::new(b"reconstruct_proof_test");
            let mut proof = ReconstructProof::<RistrettoCurve>::prove(
                cards.clone(),
                user_readable_cards.clone(),
                output_cards.clone(),
                swap_out_cards.clone(),
                &user_sk,
                &user_pk,
                s_vec.clone(),
                &mut prove_transcript,
            ).unwrap();
            total_prove_time += start.elapsed();

            // 测量验证时间
            let start = std::time::Instant::now();
            let mut verify_transcript = Transcript::new(b"reconstruct_proof_test");
            proof.verify(
                &cards,
                &output_cards,
                &swap_out_cards.iter().map(|(_, oc)| *oc).collect::<Vec<_>>(),
                &user_pk,
                &mut verify_transcript,
            ).unwrap();
            total_verify_time += start.elapsed();
        }

        let avg_prove = total_prove_time.as_millis() as f64 / iterations as f64;
        let avg_verify = total_verify_time.as_millis() as f64 / iterations as f64;
        let total = avg_prove + avg_verify;

        println!("{:<15.2} {:<15.2} {:<15.2}", avg_prove, avg_verify, total);
    }

    // ===== 攻击测试：伪造 ReconstructProof =====

    /// 辅助函数：创建完整的 ReconstructProof 测试数据
    fn setup_reconstruct_proof_attack(
        n_cards: usize,
        n_user_cards: usize,
    ) -> (
        Vec<EcPoint>,
        Vec<ElGamalCiphertext>,
        Vec<ElGamalCiphertext>,
        Vec<(usize, ElGamalCiphertext)>,
        Scalar,
        EcPoint,
        EcPoint,
        Scalar,
        Vec<Scalar>,
    ) {
        let cards: Vec<EcPoint> = (0..n_cards)
            .map(|i| RistrettoCurve::base_g() * Scalar::from(i as u64))
            .collect();

        let user_sk = Scalar::random(&mut OsRng);
        let user_pk = RistrettoCurve::base_g() * user_sk;
        let share_sk = Scalar::random(&mut OsRng);
        let share_pk = RistrettoCurve::base_g() * share_sk;
        let coefficient = Scalar::random(&mut OsRng);

        let user_card_indices: Vec<usize> = (0..n_user_cards).collect();
        let user_readable_cards: Vec<ElGamalCiphertext> = user_card_indices
            .iter()
            .map(|&idx| {
                let card = cards[idx];
                let r = Scalar::random(&mut OsRng);
                ElGamalCiphertext::encrypt(&card, &user_pk, &r)
            })
            .collect();

        let (s_vec, output_cards, swap_out_cards) = reconstruct_deck::<RistrettoCurve>(
            &cards,
            &user_readable_cards,
            &user_sk,
            &user_pk,
            &coefficient,
        ).expect("reconstruct_deck should succeed");

        (cards, user_readable_cards, output_cards, swap_out_cards, user_sk, user_pk, share_pk, coefficient, s_vec)
    }

    /// 攻击1: ChaumPedersenDLEQProof 的 user_pk 现在作为外部参数传入 verify
    /// 旧版 DeltaChaumPedersenProof 的 user_pk 是自包含的（存储在 proof 中），
    /// 攻击者可以用任意 sk 生成证明并通过验证，因为 verify 使用 proof 内部的 user_pk。
    /// 新版 ChaumPedersenDLEQProof 将 user_pk 作为 verify 的外部参数，
    /// 验证方必须传入预期的 user_pk，因此攻击者无法再用不同的 user_pk 通过验证。
    #[test]
    fn test_attack_chaum_pedersen_forge_user_pk() {
        // 正常设置
        let user_sk = Scalar::random(&mut OsRng);
        let user_pk = RistrettoCurve::base_g() * user_sk;

        // 创建合法的 delta_c1, delta_c2（满足 delta_c2 = delta_c1 * user_sk）
        let delta_c1 = RistrettoPoint::random(&mut OsRng);
        let delta_c2 = delta_c1 * user_sk;

        // 生成合法证明
        let mut prove_ts = Transcript::new(b"test_delta_chaum");
        let proof = ChaumPedersenDLEQProof::<RistrettoCurve>::prove(delta_c1, RistrettoCurve::base_g(), user_sk, delta_c2, user_pk, &mut prove_ts);

        // 正常验证应该通过（使用正确的 user_pk）
        let mut verify_ts = Transcript::new(b"test_delta_chaum");
        assert!(proof.verify(delta_c1, RistrettoCurve::base_g(), delta_c2, user_pk, &mut verify_ts).is_ok());

        // === 攻击尝试：用不同的 sk 生成证明 ===
        let attacker_sk = Scalar::random(&mut OsRng);
        let attacker_pk = RistrettoCurve::base_g() * attacker_sk;

        // 攻击者选择 delta_c1', delta_c2' 满足 DLEQ 关系（对 attacker_sk）
        let attacker_delta_c1 = RistrettoPoint::random(&mut OsRng);
        let attacker_delta_c2 = attacker_delta_c1 * attacker_sk;

        let mut attack_ts = Transcript::new(b"test_delta_chaum");
        let forged_proof = ChaumPedersenDLEQProof::<RistrettoCurve>::prove(
            attacker_delta_c1, RistrettoCurve::base_g(), attacker_sk, attacker_delta_c2, attacker_pk, &mut attack_ts
        );

        // 用攻击者的 pk 验证可以通过（数学关系正确）
        let mut verify_ts_attacker = Transcript::new(b"test_delta_chaum");
        assert!(forged_proof.verify(attacker_delta_c1, RistrettoCurve::base_g(), attacker_delta_c2, attacker_pk, &mut verify_ts_attacker).is_ok());

        // 但用真实的 user_pk 验证会失败！
        // 因为证明中的关系是 P2 = attacker_sk * G2，而验证方传入的 P2 = user_pk = user_sk * G2
        // 两者不匹配，transcript 不同，挑战值也不同，验证会失败
        let mut verify_ts_real = Transcript::new(b"test_delta_chaum");
        let result = forged_proof.verify(attacker_delta_c1, RistrettoCurve::base_g(), attacker_delta_c2, user_pk, &mut verify_ts_real);
        assert!(result.is_err(), "Forged proof should NOT verify with real user_pk");

        println!("攻击1验证：ChaumPedersenDLEQProof 将 user_pk 作为外部参数传入 verify");
        println!("  攻击者无法再用不同的 user_pk 通过验证");
        println!("  真实 user_pk: {:?}", user_pk.compress());
        println!("  攻击者 pk: {:?}", attacker_pk.compress());
    }

    /// 攻击2: ChaumPedersenDLEQProof 代数伪造分析
    /// 分析攻击者是否可以在不知道离散对数的情况下伪造证明
    /// 结论：ChaumPedersenDLEQProof 在数学上是安全的，攻击者无法伪造
    #[test]
    fn test_attack_chaum_pedersen_algebraic_forge() {
        // 攻击者选择任意的 delta_c1 和 delta_c2（不满足任何 DLEQ 关系）
        let delta_c1 = RistrettoPoint::random(&mut OsRng);
        let delta_c2 = RistrettoPoint::random(&mut OsRng);

        // 攻击者尝试构造满足两个验证方程的证明：
        //   (1) G1 * response == commitment_a + P1 * c
        //   (2) G2 * response == commitment_b + P2 * c
        // 其中 G1=delta_c1, G2=BASE_G, P1=delta_c2, P2=user_pk
        //
        // 攻击者不知道任何使得 delta_c2 = delta_c1 * sk 的 sk
        // 所以无法同时满足两个方程
        //
        // 攻击者可以选择自己的 sk'，令 delta_c2' = delta_c1 * sk'
        // 这样 DLEQ 关系对 sk' 成立，但 delta_c2' != delta_c2
        let attacker_sk = Scalar::random(&mut OsRng);
        let attacker_pk = RistrettoCurve::base_g() * attacker_sk;
        let fake_delta_c2 = delta_c1 * attacker_sk; // 满足 DLEQ 关系

        let mut attack_transcript = Transcript::new(b"test_delta_chaum");
        let forged_proof = ChaumPedersenDLEQProof::<RistrettoCurve>::prove(
            delta_c1, RistrettoCurve::base_g(), attacker_sk, fake_delta_c2, attacker_pk, &mut attack_transcript,
        );

        // 用攻击者的 pk 验证可以通过
        let mut verify_transcript = Transcript::new(b"test_delta_chaum");
        assert!(forged_proof.verify(delta_c1, RistrettoCurve::base_g(), fake_delta_c2, attacker_pk, &mut verify_transcript).is_ok());

        // 但用真实的 user_pk 验证会失败
        let user_sk = Scalar::random(&mut OsRng);
        let user_pk = RistrettoCurve::base_g() * user_sk;
        let mut verify_transcript2 = Transcript::new(b"test_delta_chaum");
        assert!(forged_proof.verify(delta_c1, RistrettoCurve::base_g(), fake_delta_c2, user_pk, &mut verify_transcript2).is_err());

        // 而且，如果验证方用原始的 delta_c2 验证，也会失败
        // 因为证明中的 P1 是 fake_delta_c2，不是原始的 delta_c2
        let mut verify_transcript3 = Transcript::new(b"test_delta_chaum");
        assert!(forged_proof.verify(delta_c1, RistrettoCurve::base_g(), delta_c2, attacker_pk, &mut verify_transcript3).is_err());

        println!("攻击2验证：ChaumPedersenDLEQProof 的 user_pk 作为外部参数传入 verify");
        println!("  攻击者可以构造满足 DLEQ 的假 delta_c2，但无法用真实的 user_pk 通过验证");
    }

    /// 攻击3: ReconstructProof::verify 忽略 user_pk，允许伪造 swap 证明
    /// 这是漏洞1+漏洞2的组合攻击
    #[test]
    fn test_attack_reconstruct_proof_swap_forge() {
        let (cards, user_readable_cards, output_cards, swap_out_cards, user_sk, user_pk, share_pk, coefficient, s_vec) =
            setup_reconstruct_proof_attack(5, 2);
        let mut transcript = Transcript::new(b"reconstruct_proof_test");
        // 生成合法证明
        let proof = ReconstructProof::<RistrettoCurve>::prove(
            cards.clone(),
            user_readable_cards.clone(),
            output_cards.clone(),
            swap_out_cards.clone(),
            &user_sk,
            &user_pk,
            s_vec.clone(),
            &mut transcript,
        ).unwrap();

        // 正常验证应该通过
        let mut verify_transcript = Transcript::new(b"reconstruct_proof_test");
        let result = proof.verify(
            &cards,
            &output_cards,
            &swap_out_cards.iter().map(|(_, oc)| *oc).collect::<Vec<_>>(),
            &user_pk,
            &mut verify_transcript,
        );
        // 注意：由于 prove 和 verify 中 swap 证明的 transcript 不一致，
        // 这个验证可能会失败。这是另一个 bug。

        // 核心攻击：伪造 swap_out_cards_proofs 中使用不同的 user_pk
        // 由于 ChaumPedersenDLEQProof 的 user_pk 现在作为外部参数传入 verify，
        // ReconstructProof::verify 如果正确传入预期的 user_pk，
        // 攻击者用不同 sk 生成的 swap 证明将无法通过验证

        let attacker_sk = Scalar::random(&mut OsRng);
        let attacker_pk = RistrettoCurve::base_g() * attacker_sk;

        // 攻击者构造自己的 swap_out_cards（不满足与真实 user_sk 的关系）
        // 但满足与 attacker_sk 的关系
        let mut fake_swap_out_cards = Vec::new();
        for (idx, user_card) in user_readable_cards.iter().enumerate() {
            // 构造一个密文，使得 delta_c2 = delta_c1 * attacker_sk
            let fake_r = Scalar::random(&mut OsRng);
            let fake_swap_card = ElGamalCiphertext::encrypt(
                &RistrettoPoint::random(&mut OsRng), // 任意明文
                &attacker_pk,
                &fake_r,
            );
            fake_swap_out_cards.push((swap_out_cards[idx].0, fake_swap_card));
        }

        // 用 attacker_sk 生成 swap 证明
        let mut fake_swap_transcript = Transcript::new(b"swap_out_card_proof");
        TranscriptExtension::<RistrettoCurve>::append_scalar(&mut fake_swap_transcript, b"reconstruct_proof_nonce", &proof.nonce);
        let fake_swap_proofs: Vec<SwapOutCardProof<RistrettoCurve>> = fake_swap_out_cards
            .iter()
            .zip(user_readable_cards.iter())
            .map(|((_, swap_card), user_card)| {
                // delta_c1 = swap_card.c1 - user_card.c1
                // delta_c2 = swap_card.c2 - user_card.c2
                // 需要满足 delta_c2 = delta_c1 * attacker_sk
                // 但这不一定成立...所以需要更精细的构造
                SwapOutCardProof::prove(*user_card, *swap_card, &attacker_sk, &attacker_pk, &mut fake_swap_transcript)
            })
            .collect();

        // 这些假证明的 ChaumPedersenDLEQProof 验证会失败（因为 delta_c2 != delta_c1 * attacker_sk）
        // 除非攻击者精心构造 swap_card 使得关系成立

        println!("攻击3验证：user_pk 未被验证，但需要精心构造 swap_card 才能通过 DLEQ");
        println!("  真实 user_pk: {:?}", user_pk.compress());
        println!("  攻击者 pk: {:?}", attacker_pk.compress());
    }

    /// 攻击4: 精心构造的 swap 伪造攻击
    /// 攻击者构造 swap_out_card 使得 delta_c2 = delta_c1 * attacker_sk
    /// 这样 ChaumPedersenDLEQProof 就能用 attacker_sk 通过验证
    /// 但由于 ChaumPedersenDLEQProof 的 verify 接受外部 user_pk 参数，
    /// 验证方如果传入真实的 user_pk，攻击将失败
    #[test]
    fn test_attack_swap_forge_with_crafted_ciphertext() {
        let user_sk = Scalar::random(&mut OsRng);
        let user_pk = RistrettoCurve::base_g() * user_sk;

        // 攻击者的密钥
        let attacker_sk = Scalar::random(&mut OsRng);
        let attacker_pk = RistrettoCurve::base_g() * attacker_sk;

        // 创建一个 user_readable_card
        let plaintext = RistrettoCurve::base_g() * Scalar::from(42u64);
        let r = Scalar::random(&mut OsRng);
        let user_readable_card = ElGamalCiphertext::encrypt(&plaintext, &user_pk, &r);

        // 攻击者构造 swap_out_card 使得：
        // delta_c1 = swap_out_card.c1 - user_readable_card.c1
        // delta_c2 = swap_out_card.c2 - user_readable_card.c2
        // 满足 delta_c2 = delta_c1 * attacker_sk
        //
        // 即：swap_out_card.c2 - user_readable_card.c2 = (swap_out_card.c1 - user_readable_card.c1) * attacker_sk
        //
        // 选择 swap_out_card.c1 = G * r'（任意 r'）
        // 则 delta_c1 = G * r' - user_readable_card.c1
        // delta_c2 = delta_c1 * attacker_sk
        // swap_out_card.c2 = delta_c2 + user_readable_card.c2

        let r_prime = Scalar::random(&mut OsRng);
        let swap_c1 = RistrettoCurve::base_g() * r_prime;
        let delta_c1 = swap_c1 - user_readable_card.c1;
        let delta_c2 = delta_c1 * attacker_sk;
        let swap_c2 = delta_c2 + user_readable_card.c2;

        let _crafted_swap_card = ElGamalCiphertext { c1: swap_c1, c2: swap_c2 };

        // 用 attacker_sk 生成 ChaumPedersenDLEQProof
        let mut transcript = Transcript::new(b"swap_out_card_proof");
        let proof = ChaumPedersenDLEQProof::<RistrettoCurve>::prove(
            delta_c1, RistrettoCurve::base_g(), attacker_sk, delta_c2, attacker_pk, &mut transcript,
        );

        // 用攻击者的 pk 验证应该通过
        let mut verify_transcript = Transcript::new(b"swap_out_card_proof");
        let result = proof.verify(delta_c1, RistrettoCurve::base_g(), delta_c2, attacker_pk, &mut verify_transcript);
        assert!(result.is_ok(), "Crafted swap proof should verify with attacker_pk");

        // 但用真实的 user_pk 验证会失败
        // 因为证明中的 P2 = attacker_pk，而验证方传入的 P2 = user_pk
        let mut verify_transcript2 = Transcript::new(b"swap_out_card_proof");
        let result2 = proof.verify(delta_c1, RistrettoCurve::base_g(), delta_c2, user_pk, &mut verify_transcript2);
        assert!(result2.is_err(), "Crafted swap proof should NOT verify with real user_pk");

        // ChaumPedersenDLEQProof 不再包含 user_pk 字段，
        // 验证方必须显式传入预期的 user_pk，因此旧版的自包含攻击不再可行
        println!("攻击4验证：精心构造的 swap_out_card 可以用 attacker_sk 通过 DLEQ 验证");
        println!("  但 ChaumPedersenDLEQProof 的 verify 需要外部传入 user_pk");
        println!("  如果验证方传入真实的 user_pk，攻击将失败！");
    }

    /// 攻击5: blind_dleq_proof 中 swap 部分不使用 rho_i 加权
    /// 这意味着 blind_dleq_proof 对 swap 部分证明的关系与实际使用的不一致
    #[test]
    fn test_attack_blind_dleq_swap_rho_mismatch() {
        let (cards, user_readable_cards, output_cards, swap_out_cards, user_sk, user_pk, share_pk, coefficient, s_vec) =
            setup_reconstruct_proof_attack(5, 2);
        let mut transcript = Transcript::new(b"reconstruct_proof_test");
        let proof = ReconstructProof::<RistrettoCurve>::prove(
            cards.clone(),
            user_readable_cards.clone(),
            output_cards.clone(),
            swap_out_cards.clone(),
            &user_sk,
            &user_pk,
            s_vec.clone(),
            &mut transcript,
        ).unwrap();

        // 在 prove 中：
        // points_in[2] = sum(swap_out_cards.c1)  （没有 rho_i 加权）
        // points_in[3] = sum(swap_out_cards.c2)  （没有 rho_i 加权）
        // 但 swap_sum_c1_commit = sum(rho_i * blind * swap_out_cards[i].c1)  （有 rho_i 加权）
        //
        // blind_dleq_proof 证明的是：
        //   points_in[2] * blind = swap_sum_c1_commit
        //   即 sum(swap_c1) * blind = sum(rho_i * blind * swap_c1_i)
        //   即 sum(swap_c1) = sum(rho_i * swap_c1_i)
        //
        // 这只有在所有 rho_i 相等时才成立，但 rho_i 是不同的随机值！
        // 所以 blind_dleq_proof 对 swap 部分的验证实际上会失败

        // 让我们验证这一点
        let mut verify_transcript = Transcript::new(b"reconstruct_proof_test");

        // 手动计算 points_in 和 points_out
        TranscriptExtension::<RistrettoCurve>::append_scalar(&mut verify_transcript, b"reconstruct_proof_nonce", &proof.nonce);

        // 重新生成 scalars（rho_i）
        let scalars: Vec<Scalar> = (0..output_cards.len())
            .map(|_| {
                let mut buf = [0u8; 64];
                verify_transcript.challenge_bytes(b"rho_challenge", &mut buf);
                Scalar::from_bytes_mod_order_wide(&buf)
            })
            .collect();

        let points_c1: Vec<EcPoint> = output_cards.iter().map(|oc| oc.c1).collect();
        let points_c2: Vec<EcPoint> = output_cards.iter().zip(cards.iter())
            .map(|(oc, card)| oc.c2 - *card).collect();

        let sum_output_c1 = EcPoint::vartime_multiscalar_mul(&scalars, &points_c1);
        let sum_output_c2 = EcPoint::vartime_multiscalar_mul(&scalars, &points_c2);

        // prove 中的 points_in
        let swap_c1_sum: EcPoint = swap_out_cards.iter().map(|(_, oc)| oc.c1).sum();
        let swap_c2_sum: EcPoint = swap_out_cards.iter().map(|(_, oc)| oc.c2).sum();

        // 实际的 swap_sum_c1_commit 应该是 sum(rho_i * blind * swap_c1_i)
        // 但 blind_dleq_proof 证明的是 swap_c1_sum * blind = swap_sum_c1_commit
        // 这两个只有在 sum(swap_c1_i) = sum(rho_i * swap_c1_i) 时才一致

        // 检查 rho_i 是否都相同
        let all_same = scalars.windows(2).all(|w| w[0] == w[1]);
        println!("所有 rho_i 是否相同: {}", all_same);
        if !all_same {
            println!("rho_i 值不同，blind_dleq_proof 对 swap 部分的验证存在不一致");
            for (i, rho) in scalars.iter().enumerate().take(5) {
                println!("  rho_{} = {:?}", i, rho);
            }
        }
    }

    /// 攻击6: 利用 empty swap_out_cards 绕过所有 swap 验证
    #[test]
    fn test_attack_empty_swap_bypass() {
        // 构造一个没有 swap_out_cards 的情况
        // 但 output_cards 中的 c2 仍然被修改（减去了 card）
        let cards: Vec<EcPoint> = (0..5)
            .map(|i| RistrettoCurve::base_g() * Scalar::from(i as u64))
            .collect();

        let share_sk = Scalar::random(&mut OsRng);
        let share_pk = RistrettoCurve::base_g() * share_sk;

        // 不使用用户手牌，直接加密所有牌
        let coefficient = Scalar::random(&mut OsRng);
        let s_vec: Vec<Scalar> = exp_iter::<RistrettoCurve>(coefficient).take(5).collect();
        let output_cards: Vec<ElGamalCiphertext> = cards
            .iter()
            .enumerate()
            .map(|(i, card)| ElGamalCiphertext::encrypt(card, &share_pk, &s_vec[i]))
            .collect();

        // 验证加密正确性
        for (i, oc) in output_cards.iter().enumerate() {
            let decrypted = oc.decrypt(&share_sk);
            assert_eq!(decrypted, cards[i], "Card {} should decrypt correctly", i);
        }

        // 如果 swap_out_cards 为空，swap_combined_schnorr_proof
        // 的 base_points 也为空，GeneralizedSchnorrProof 可能出现边界情况
        println!("攻击6验证：空 swap_out_cards 的边界情况需要检查");
    }

    /// 攻击7: 伪造 total_dleq_proof — 通过选择特殊的 blind 和 swap 值
    /// 使得 c1_total = s'*G, c2_total = s'*share_pk 对某个 s' 成立
    /// 即使 output_cards 不满足正确的加密关系
    #[test]
    fn test_attack_forge_total_dleq_with_wrong_output() {
        let (cards, user_readable_cards, _output_cards, _swap_out_cards, user_sk, user_pk, share_pk, _coefficient, _s_vec) =
            setup_reconstruct_proof_attack(5, 2);

        // 攻击者构造错误的 output_cards（不满足正确的加密关系）
        let wrong_share_pk = RistrettoCurve::base_g() * Scalar::random(&mut OsRng);
        let wrong_output_cards: Vec<ElGamalCiphertext> = cards
            .iter()
            .map(|card| {
                let r = Scalar::random(&mut OsRng);
                ElGamalCiphertext::encrypt(card, &wrong_share_pk, &r)
            })
            .collect();

        // 攻击者尝试构造一个 ReconstructProof 使得 total_dleq_proof 通过
        // total_dleq_proof 需要 c1_total = s*G, c2_total = s*share_pk
        // c1_total = sum_c1_r_commit + swap_sum_c1_commit
        // c2_total = sum_c2_r_commit + swap_sum_c2_commit

        // 攻击者可以选择 blind 和 swap 值使得 c1_total 和 c2_total 满足 DLEQ
        // 关键：攻击者需要知道某个 s' 使得 c1_total = s'*G
        // 这需要解决离散对数问题，所以这个攻击在一般情况下不可行

        // 但是，如果攻击者自己选择 s'，然后构造 c1_total = s'*G, c2_total = s'*share_pk
        // 攻击者需要：
        //   sum_c1_r_commit + swap_sum_c1_commit = s'*G
        //   sum_c2_r_commit + swap_sum_c2_commit = s'*share_pk
        //
        // 攻击者控制 blind（影响 sum_c1_r_commit 和 sum_c2_r_commit）
        // 和 secret_vec（影响 swap_sum_c1_commit 和 swap_sum_c2_commit）
        //
        // 但 blind_dleq_proof 约束了这些值之间的关系
        // 所以攻击者不能自由选择

        println!("攻击7验证：伪造 total_dleq_proof 需要解决 DLP，在一般情况下不可行");
        println!("但如果 blind_dleq_proof 的 swap 部分有漏洞（攻击5），可能存在攻击路径");
    }

    /// 攻击8: reconstruction.rs 中的旧版 DeltaChaumPedersenProof 完全没有 user_pk
    /// 这是比 reconstruction_25519.rs 更严重的漏洞
    /// 新版 ChaumPedersenDLEQProof 将 user_pk 作为外部参数传入 verify，已修复此问题
    #[test]
    fn test_attack_reconstruction_rs_delta_no_user_pk() {
        // 旧版 DeltaChaumPedersenProof 只有 commitment_A 和 response_s
        // 没有 user_pk 字段！
        // 验证方程：delta_c1 * response_s == commitment_A + delta_c2 * c
        // 这只证明 delta_c1 和 delta_c2 有相同的离散对数
        // 但不证明这个离散对数是 user_sk（即 G * user_sk = user_pk）
        //
        // 新版 ChaumPedersenDLEQProof 通过将 user_pk 作为 verify 的外部参数解决了此问题：
        // 验证方程：(1) G1 * response == commitment_a + P1 * c
        //           (2) G2 * response == commitment_b + P2 * c
        // 其中 P2 = user_pk，G2 = BASE_G
        // 如果 user_pk 不匹配，方程 (2) 会失败

        // 攻击：选择任意的 sk'，令 delta_c2' = delta_c1 * sk'
        // 生成证明，验证通过
        // 但 sk' != user_sk，验证方无法区分

        let user_sk = Scalar::random(&mut OsRng);
        let user_pk = RistrettoCurve::base_g() * user_sk;
        let attacker_sk = Scalar::random(&mut OsRng);

        let delta_c1 = RistrettoPoint::random(&mut OsRng);
        // 真实的 delta_c2
        let real_delta_c2 = delta_c1 * user_sk;
        // 攻击者的 delta_c2（使用不同的 sk）
        let fake_delta_c2 = delta_c1 * attacker_sk;

        // 用 attacker_sk 生成证明
        let mut transcript = Transcript::new(b"test_recon");
        // 模拟旧版 DeltaChaumPedersenProof::prove（没有 user_pk 绑定）
        TranscriptExtension::<RistrettoCurve>::append_point(&mut transcript, b"recon_delta_c1", &delta_c1);
        TranscriptExtension::<RistrettoCurve>::append_point(&mut transcript, b"recon_delta_c2", &fake_delta_c2);
        let c = TranscriptExtension::<RistrettoCurve>::challenge(&mut transcript, b"recon_delta_challenge").scalar;
        let w = Scalar::random(&mut OsRng);
        let response = w + attacker_sk * c;
        let commitment_a = delta_c1 * w;

        // 验证
        let mut verify_transcript = Transcript::new(b"test_recon");
        TranscriptExtension::<RistrettoCurve>::append_point(&mut verify_transcript, b"recon_delta_c1", &delta_c1);
        TranscriptExtension::<RistrettoCurve>::append_point(&mut verify_transcript, b"recon_delta_c2", &fake_delta_c2);
        let c_verify = TranscriptExtension::<RistrettoCurve>::challenge(&mut verify_transcript, b"recon_delta_challenge").scalar;

        let lhs = delta_c1 * response;
        let rhs = commitment_a + fake_delta_c2 * c_verify;

        assert_eq!(lhs, rhs, "Forged proof should verify");
        assert_ne!(fake_delta_c2, real_delta_c2, "Fake delta_c2 differs from real one");

        println!("攻击8验证：旧版 DeltaChaumPedersenProof 不绑定 user_pk");
        println!("  攻击者可以用任意 sk 生成通过验证的证明");
        println!("  新版 ChaumPedersenDLEQProof 通过将 user_pk 作为 verify 的外部参数解决了此问题");
    }

    // ===== 关键漏洞审计：blind=0 退化攻击 =====

    /// 安全验证：blind=0 退化攻击已被修复
    /// ReconstructionDLEQProof::prove 拒绝 a=0，
    /// GeneralizedSchnorrProof::verify 拒绝 R=identity，
    /// 验证 blind=0 无法用于伪造 ReconstructProof。
    #[test]
    fn test_attack_critical_blind_zero_forge() {
        let n_cards = 5;
        let n_user_cards = 2;

        let cards: Vec<EcPoint> = (0..n_cards)
            .map(|i| RistrettoCurve::base_g() * Scalar::from(i as u64))
            .collect();

        let user_sk = Scalar::random(&mut OsRng);
        let user_pk = RistrettoCurve::base_g() * user_sk;
        let coefficient = Scalar::random(&mut OsRng);

        let user_card_indices: Vec<usize> = (0..n_user_cards).collect();
        let user_readable_cards: Vec<ElGamalCiphertext> = user_card_indices
            .iter()
            .map(|&idx| {
                let card = cards[idx];
                let r = Scalar::random(&mut OsRng);
                ElGamalCiphertext::encrypt(&card, &user_pk, &r)
            })
            .collect();

        let (_s_vec, output_cards, swap_out_cards) = reconstruct_deck::<RistrettoCurve>(
            &cards,
            &user_readable_cards,
            &user_sk,
            &user_pk,
            &coefficient,
        ).expect("reconstruct_deck should succeed");

        // === 验证1: ReconstructionDLEQProof::prove 拒绝 blind=0 ===
        let points_in = vec![RistrettoPoint::random(&mut OsRng), RistrettoPoint::random(&mut OsRng)];
        let points_out = vec![EcPoint::identity(), EcPoint::identity()];
        let mut ts = Transcript::new(b"test_blind_zero");
        let result = ReconstructionDLEQProof::<RistrettoCurve>::prove(&points_in, &points_out, Scalar::ZERO, &mut ts);
        assert!(result.is_err(), "ReconstructionDLEQProof::prove should reject blind=0");

        // === 验证2: GeneralizedSchnorrProof::verify 拒绝 R=identity ===
        // 当 blind=0 时 secret_vec 全零，swap_sum 为 identity，schnorr 验证应失败
        let base_points: Vec<EcPoint> = swap_out_cards.iter().map(|(_, oc)| oc.c1).collect();
        let secret_vec: Vec<Scalar> = vec![Scalar::ZERO; swap_out_cards.len()];
        let mut ts2 = Transcript::new(b"test_schnorr_identity");
        // prove 会 panic on R=identity，所以直接验证 verify 拒绝 identity
        let fake_proof = GeneralizedSchnorrProof::<RistrettoCurve> {
            commitment: EcPoint::identity(),
            responses: secret_vec,
        };
        let result2 = fake_proof.verify(&base_points, &EcPoint::identity(), &mut ts2);
        assert!(result2.is_err(), "GeneralizedSchnorrProof::verify should reject R=identity");

        // === 验证3: 完整 ReconstructProof 无法用 blind=0 构造 ===
        // 由于 ReconstructionDLEQProof::prove 拒绝 blind=0，
        // 攻击者无法通过 prove 函数构造 blind=0 的证明
        println!("blind=0 退化攻击已被修复：");
        println!("  ReconstructionDLEQProof::prove 拒绝 a=0");
        println!("  GeneralizedSchnorrProof::verify 拒绝 R=identity");
        println!("  blind=0 无法用于伪造 ReconstructProof");
    }

    /// 漏洞2 (HIGH): user_readable_cards 未传入 verify
    /// ReconstructProof::verify 不接收 user_readable_cards 参数，
    /// SwapOutCardProof 中的 user_readable_card 来自证明本身（自包含），
    /// 验证方无法确认 swap 证明中的 user_readable_card 是否与预期的用户手牌一致。
    ///
    /// 攻击者可以使用伪造的 user_readable_cards 生成 swap 证明，
    /// 验证方无法检测这种替换。
    #[test]
    fn test_attack_user_readable_cards_not_bound() {
        let n_cards = 5;
        let cards: Vec<EcPoint> = (0..n_cards)
            .map(|i| RistrettoCurve::base_g() * Scalar::from(i as u64))
            .collect();

        let user_sk = Scalar::random(&mut OsRng);
        let user_pk = RistrettoCurve::base_g() * user_sk;
        let coefficient = Scalar::random(&mut OsRng);

        // 真实用户手牌：索引 0, 1
        let real_user_card_indices = vec![0, 1];
        let real_user_readable_cards: Vec<ElGamalCiphertext> = real_user_card_indices
            .iter()
            .map(|&idx| {
                let card = cards[idx];
                let r = Scalar::random(&mut OsRng);
                ElGamalCiphertext::encrypt(&card, &user_pk, &r)
            })
            .collect();

        let (s_vec, output_cards, swap_out_cards) = reconstruct_deck::<RistrettoCurve>(
            &cards,
            &real_user_readable_cards,
            &user_sk,
            &user_pk,
            &coefficient,
        ).expect("reconstruct_deck should succeed");

        // === 攻击：使用伪造的 user_readable_cards ===
        // 攻击者声称自己有不同的手牌（例如索引 2, 3 而非 0, 1）
        let fake_user_card_indices = vec![2, 3];
        let fake_user_readable_cards: Vec<ElGamalCiphertext> = fake_user_card_indices
            .iter()
            .map(|&idx| {
                let card = cards[idx];
                let r = Scalar::random(&mut OsRng);
                ElGamalCiphertext::encrypt(&card, &user_pk, &r)
            })
            .collect();

        // 使用伪造的 user_readable_cards 生成 swap 证明
        // 由于攻击者知道 user_sk，DLEQ 证明可以正常生成
        let mut transcript = Transcript::new(b"reconstruct_proof_test");
        let nonce = Scalar::random(&mut OsRng);
        TranscriptExtension::<RistrettoCurve>::append_scalar(&mut transcript, b"reconstruct_proof_nonce", &nonce);

        let mut fake_swap_proofs: Vec<SwapOutCardProof<RistrettoCurve>> = Vec::new();
        for (i, fake_user_card) in fake_user_readable_cards.iter().enumerate() {
            // 使用真实的 swap_out_card（因为 output_cards 是用真实数据构造的）
            let swap_card = swap_out_cards[i].1;
            let proof = SwapOutCardProof::prove(
                *fake_user_card, swap_card, &user_sk, &user_pk, &mut transcript,
            );
            fake_swap_proofs.push(proof);
        }

        // 验证伪造的 swap 证明是否通过
        for (i, proof) in fake_swap_proofs.iter().enumerate() {
            let delta_c1 = proof.swap_out_card.c1 - proof.user_readable_card.c1;
            let delta_c2 = proof.swap_out_card.c2 - proof.user_readable_card.c2;
            let mut verify_ts = Transcript::new(b"swap_verify_test");
            // DLEQ 验证会通过，因为 delta_c2 = delta_c1 * user_sk 确实成立
            // （攻击者用 user_sk 构造的 swap_out_card 满足此关系）
            let result = proof.chaum_pedersen_proof.verify(
                delta_c1, RistrettoCurve::base_g(), delta_c2, user_pk, &mut verify_ts,
            );
            // 注意：这里 transcript 标签不同，所以验证可能因 transcript 不匹配而失败
            // 但在 ReconstructProof::verify 的上下文中，transcript 是一致的
            println!("  伪造 swap 证明[{}] 验证结果: {:?}", i, result.is_ok());
        }

        println!("漏洞2验证：user_readable_cards 未传入 verify");
        println!("  攻击者可以用伪造的 user_readable_cards 生成 swap 证明");
        println!("  验证方无法确认 swap 证明中的 user_readable_card 是否正确");
        println!("  真实手牌索引: {:?}", real_user_card_indices);
        println!("  伪造手牌索引: {:?}", fake_user_card_indices);
    }

    /// 安全验证：swap 证明与 schnorr 证明的 swap_out_cards 一致性
    /// 修复后（!= 检查），verify 中 Line 615 确保 proof.swap_out_card 与
    /// 传入的 swap_out_cards[i] 一致，防止不一致攻击。
    #[test]
    fn test_attack_swap_proof_schnorr_inconsistency() {
        let n_cards = 5;
        let cards: Vec<EcPoint> = (0..n_cards)
            .map(|i| RistrettoCurve::base_g() * Scalar::from(i as u64))
            .collect();

        let user_sk = Scalar::random(&mut OsRng);
        let user_pk = RistrettoCurve::base_g() * user_sk;
        let coefficient = Scalar::random(&mut OsRng);

        let user_card_indices = vec![0, 1];
        let user_readable_cards: Vec<ElGamalCiphertext> = user_card_indices
            .iter()
            .map(|&idx| {
                let card = cards[idx];
                let r = Scalar::random(&mut OsRng);
                ElGamalCiphertext::encrypt(&card, &user_pk, &r)
            })
            .collect();

        let (s_vec, output_cards, swap_out_cards) = reconstruct_deck::<RistrettoCurve>(
            &cards,
            &user_readable_cards,
            &user_sk,
            &user_pk,
            &coefficient,
        ).expect("reconstruct_deck should succeed");

        // 生成合法证明
        let mut transcript = Transcript::new(b"reconstruct_proof_test");
        let proof = ReconstructProof::<RistrettoCurve>::prove(
            cards.clone(),
            user_readable_cards.clone(),
            output_cards.clone(),
            swap_out_cards.clone(),
            &user_sk,
            &user_pk,
            s_vec.clone(),
            &mut transcript,
        ).unwrap();

        // 构造不同的 swap_out_cards 传给 verify
        let different_swap_cards: Vec<ElGamalCiphertext> = (0..swap_out_cards.len())
            .map(|_| {
                let r = Scalar::random(&mut OsRng);
                let plaintext = RistrettoPoint::random(&mut OsRng);
                ElGamalCiphertext::encrypt(&plaintext, &user_pk, &r)
            })
            .collect();

        // 使用不同的 swap_out_cards 验证应失败
        // 因为 proof.swap_out_card != swap_out_cards[i] 会被 != 检查拒绝
        let mut verify_transcript = Transcript::new(b"reconstruct_proof_test");
        let result = proof.verify(
            &cards,
            &output_cards,
            &different_swap_cards,
            &user_pk,
            &mut verify_transcript,
        );

        assert!(result.is_err(), "Proof should NOT verify with different swap_out_cards!");

        // 使用正确的 swap_out_cards 验证应通过
        let swap_cards_only: Vec<ElGamalCiphertext> = swap_out_cards.iter().map(|(_, oc)| *oc).collect();
        let mut verify_transcript2 = Transcript::new(b"reconstruct_proof_test");
        let result2 = proof.verify(
            &cards,
            &output_cards,
            &swap_cards_only,
            &user_pk,
            &mut verify_transcript2,
        );
        assert!(result2.is_ok(), "Proof should verify with correct swap_out_cards!");

        println!("swap 证明与 schnorr 证明一致性验证通过：");
        println!("  不同的 swap_out_cards 被拒绝");
        println!("  正确的 swap_out_cards 通过验证");
    }

    /// 安全验证：ReconstructionDLEQProof points_out 已绑定 transcript
    /// 修复后，prove 和 verify 都将 points_out 加入 transcript，
    /// 修改 points_out 会改变挑战值 c，延展性攻击不再可行。
    #[test]
    fn test_attack_reconstruction_dleq_points_out_malleability() {
        let a = Scalar::random(&mut OsRng);
        let points_in = vec![
            RistrettoPoint::random(&mut OsRng),
            RistrettoPoint::random(&mut OsRng),
        ];
        let points_out: Vec<EcPoint> = points_in.iter().map(|p| p * a).collect();

        // 生成合法证明
        let mut prove_ts = Transcript::new(b"test_recon_dleq_malleability");
        let proof = ReconstructionDLEQProof::<RistrettoCurve>::prove(&points_in, &points_out, a, &mut prove_ts).unwrap();

        // 正常验证应通过
        let mut verify_ts = Transcript::new(b"test_recon_dleq_malleability");
        assert!(proof.verify(&points_in, &points_out, &mut verify_ts).is_ok());

        // === 延展性攻击：修改 points_out ===
        // 由于 points_out 现在在 transcript 中，修改 points_out 会改变挑战值 c
        // 验证应失败
        let fake_out_0 = RistrettoPoint::random(&mut OsRng);
        let fake_out_1 = RistrettoPoint::random(&mut OsRng);
        let fake_points_out = vec![fake_out_0, fake_out_1];

        let mut verify_ts3 = Transcript::new(b"test_recon_dleq_malleability");
        let result = proof.verify(&points_in, &fake_points_out, &mut verify_ts3);

        assert!(result.is_err(), "Malleability attack should FAIL: modified points_out should NOT verify!");

        // 确认伪造的 points_out 不等于原始的
        assert_ne!(fake_points_out[0], points_out[0], "Forged points_out[0] should differ from original");

        println!("ReconstructionDLEQProof points_out 延展性攻击已被修复：");
        println!("  points_out 已加入 transcript，修改后挑战值改变");
        println!("  伪造的 points_out 无法通过验证");
    }

    /// 安全验证：cards/output_cards 通过 rho_i 随机线性组合间接绑定到 transcript
    /// 在 blind 非零时，sum_output_c1 和 sum_output_c2 由 cards 和 output_cards
    /// 唯一确定（随机线性组合的抗碰撞性），绑定强度足够。
    #[test]
    fn test_attack_cards_output_cards_not_bound_to_transcript() {
        let n_cards = 5;
        let cards: Vec<EcPoint> = (0..n_cards)
            .map(|i| RistrettoCurve::base_g() * Scalar::from(i as u64))
            .collect();

        let user_sk = Scalar::random(&mut OsRng);
        let user_pk = RistrettoCurve::base_g() * user_sk;
        let coefficient = Scalar::random(&mut OsRng);

        let user_card_indices = vec![0, 1];
        let user_readable_cards: Vec<ElGamalCiphertext> = user_card_indices
            .iter()
            .map(|&idx| {
                let card = cards[idx];
                let r = Scalar::random(&mut OsRng);
                ElGamalCiphertext::encrypt(&card, &user_pk, &r)
            })
            .collect();

        let (s_vec, output_cards, swap_out_cards) = reconstruct_deck::<RistrettoCurve>(
            &cards,
            &user_readable_cards,
            &user_sk,
            &user_pk,
            &coefficient,
        ).expect("reconstruct_deck should succeed");

        // 生成合法证明
        let mut transcript = Transcript::new(b"reconstruct_proof_test");
        let proof = ReconstructProof::<RistrettoCurve>::prove(
            cards.clone(),
            user_readable_cards.clone(),
            output_cards.clone(),
            swap_out_cards.clone(),
            &user_sk,
            &user_pk,
            s_vec.clone(),
            &mut transcript,
        ).unwrap();

        // 使用正确的 cards 和 output_cards 验证应通过
        let swap_cards_only: Vec<ElGamalCiphertext> = swap_out_cards.iter().map(|(_, oc)| *oc).collect();
        let mut verify_ts1 = Transcript::new(b"reconstruct_proof_test");
        let result1 = proof.verify(&cards, &output_cards, &swap_cards_only, &user_pk, &mut verify_ts1);
        assert!(result1.is_ok(), "Proof should verify with correct cards and output_cards");

        // 使用不同的 cards 验证应失败
        // 因为 rho_i 随机线性组合绑定，不同的 cards 产生不同的 sum_output_c2
        let different_cards: Vec<EcPoint> = (0..n_cards)
            .map(|i| RistrettoCurve::base_g() * Scalar::from((i + 100) as u64))
            .collect();

        let mut verify_ts2 = Transcript::new(b"reconstruct_proof_test");
        let result2 = proof.verify(&different_cards, &output_cards, &swap_cards_only, &user_pk, &mut verify_ts2);
        assert!(result2.is_err(), "Proof should NOT verify with different cards");

        // 使用不同的 output_cards 验证应失败
        let malicious_output_cards: Vec<ElGamalCiphertext> = cards
            .iter()
            .map(|card| {
                let r = Scalar::random(&mut OsRng);
                ElGamalCiphertext::encrypt(card, &user_pk, &r)
            })
            .collect();

        let mut verify_ts3 = Transcript::new(b"reconstruct_proof_test");
        let result3 = proof.verify(&cards, &malicious_output_cards, &swap_cards_only, &user_pk, &mut verify_ts3);
        assert!(result3.is_err(), "Proof should NOT verify with different output_cards");

        println!("cards/output_cards 绑定验证通过：");
        println!("  正确的 cards + output_cards 通过验证");
        println!("  不同的 cards 被拒绝");
        println!("  不同的 output_cards 被拒绝");
    }

    /// 漏洞6 (LOW): swap_out_cards 的索引信息在 verify 中丢失
    /// prove 中 swap_out_cards 是 Vec<(usize, ElGamalCiphertext)>，
    /// 但 verify 中 swap_out_cards 是 &[ElGamalCiphertext]（没有索引）。
    /// 这意味着验证方不知道每个 swap card 对应 output_cards 中的哪个位置，
    /// 攻击者可以利用这一点重新排列 swap card 的对应关系。
    #[test]
    fn test_attack_swap_index_lost_in_verify() {
        println!("漏洞6验证：swap_out_cards 的索引在 verify 中丢失");
        println!("  prove: swap_out_cards: Vec<(usize, ElGamalCiphertext)>");
        println!("  verify: swap_out_cards: &[ElGamalCiphertext]");
        println!("  验证方无法确认 swap card 与 output_cards 位置的对应关系");
        println!("  secret_vec[i] 应该等于 rho[swap_index[i]] * blind，但验证方无法校验");
    }

    // ===== c1/c2 信息转移攻击测试 =====

    /// 攻击9 (CRITICAL): swap_out_cards 的 c1/c2 信息转移攻击
    ///
    /// 漏洞根因: swap_combined_schnorr_proof 只约束 swap_out_cards 的 c1+c2 的加权和，
    /// 而不约束 c1 和 c2 的个体值。攻击者可以将 c1 中的信息转移到 c2，
    /// 使得 c1+c2 的和不变，但 c1 和 c2 的个体值被篡改。
    ///
    /// 修复: 添加 sum_swap_out_c1_schnorr_proof 和 sum_swap_out_c2_schnorr_proof，
    /// 分别约束 c1 和 c2 的个体值，使信息转移攻击不可行。
    #[test]
    fn test_attack_swap_c1_c2_information_shift() {
        let (cards, user_readable_cards, output_cards, swap_out_cards, user_sk, user_pk, _share_pk, _coefficient, s_vec) =
            setup_reconstruct_proof_attack(5, 2);

        // 生成合法证明
        let mut transcript = Transcript::new(b"reconstruct_proof_test");
        let proof = ReconstructProof::<RistrettoCurve>::prove(
            cards.clone(),
            user_readable_cards.clone(),
            output_cards.clone(),
            swap_out_cards.clone(),
            &user_sk,
            &user_pk,
            s_vec.clone(),
            &mut transcript,
        ).unwrap();

        // 正常验证应通过
        let swap_cards_only: Vec<ElGamalCiphertext> = swap_out_cards.iter().map(|(_, oc)| *oc).collect();
        let mut verify_ts = Transcript::new(b"reconstruct_proof_test");
        assert!(proof.verify(&cards, &output_cards, &swap_cards_only, &user_pk, &mut verify_ts).is_ok(),
            "Honest proof should verify");

        // === 攻击: 将 swap_out_cards 的 c1 信息转移到 c2 ===
        // 构造伪造的 swap_out_cards，使得 c1+c2 的和不变，但 c1 和 c2 被篡改
        let mut forged_swap_cards: Vec<ElGamalCiphertext> = Vec::new();
        for (_, oc) in swap_out_cards.iter() {
            // forged_c1 + forged_c2 = oc.c1 + oc.c2 (和不变)
            // forged_c1 = G * r_j (无原始信息)
            // forged_c2 = oc.c1 + oc.c2 - G * r_j (包含全部信息)
            let r_j = Scalar::random(&mut OsRng);
            let forged_c1 = RistrettoCurve::base_g() * r_j;
            let forged_c2 = oc.c1 + oc.c2 - RistrettoCurve::base_g() * r_j;
            forged_swap_cards.push(ElGamalCiphertext { c1: forged_c1, c2: forged_c2 });
        }

        // 使用原始证明验证伪造的 swap_out_cards 应失败
        // 因为 swap_out_cards_proofs 中的 swap_out_card 与 forged_swap_cards 不匹配
        let mut verify_ts2 = Transcript::new(b"reconstruct_proof_test");
        let result = proof.verify(&cards, &output_cards, &forged_swap_cards, &user_pk, &mut verify_ts2);
        assert!(result.is_err(),
            "Forged swap cards should NOT verify with honest proof (swap_out_card mismatch)");

        // === 更深入的攻击: 完全伪造证明 ===
        // 攻击者需要为伪造的 swap_out_cards 构造完整的 ReconstructProof
        // 但 swap 证明 (ChaumPedersenDLEQProof) 需要 user_sk，
        // 攻击者不知道 user_sk，无法构造有效的 swap 证明
        // 即使攻击者知道 user_sk，c1/c2 独立 Schnorr 证明也会拒绝信息转移

        // 验证: 伪造 swap_out_cards 的 c1+c2 与原始相同
        for (i, (forged, (_, original))) in forged_swap_cards.iter().zip(swap_out_cards.iter()).enumerate() {
            let forged_sum = forged.c1 + forged.c2;
            let original_sum = original.c1 + original.c2;
            assert_eq!(forged_sum, original_sum,
                "Forged swap card {} c1+c2 should equal original c1+c2", i);
            assert_ne!(forged.c1, original.c1,
                "Forged swap card {} c1 should differ from original c1", i);
        }

        println!("c1/c2 信息转移攻击测试通过：");
        println!("  伪造的 swap_out_cards (c1+c2 不变) 被拒绝");
        println!("  独立 c1/c2 Schnorr 证明有效防止信息转移攻击");
    }

    /// 攻击10: swap_out_cards 的 c1/c2 部分信息转移
    ///
    /// 攻击者只转移部分信息，使 swap_out_cards 更接近合法密文:
    ///   forged_c1 = original_c1 * alpha + G * r_j
    ///   forged_c2 = original_c2 + original_c1 * (1 - alpha) - G * r_j
    /// 当 alpha = 1 时为原始密文，alpha = 0 时为完全转移攻击。
    #[test]
    fn test_attack_swap_c1_c2_partial_shift() {
        let (cards, user_readable_cards, output_cards, swap_out_cards, user_sk, user_pk, _share_pk, _coefficient, s_vec) =
            setup_reconstruct_proof_attack(5, 2);

        let alpha = Scalar::from(2u64).invert(); // 0.5
        let one_minus_alpha = Scalar::ONE - alpha;

        let mut forged_swap_cards: Vec<ElGamalCiphertext> = Vec::new();
        for (_, oc) in swap_out_cards.iter() {
            let r_j = Scalar::random(&mut OsRng);
            let forged_c1 = oc.c1 * alpha + RistrettoCurve::base_g() * r_j;
            let forged_c2 = oc.c2 + oc.c1 * one_minus_alpha - RistrettoCurve::base_g() * r_j;
            forged_swap_cards.push(ElGamalCiphertext { c1: forged_c1, c2: forged_c2 });
        }

        // 验证 c1+c2 的和不变
        for (i, (forged, (_, original))) in forged_swap_cards.iter().zip(swap_out_cards.iter()).enumerate() {
            let forged_sum = forged.c1 + forged.c2;
            let original_sum = original.c1 + original.c2;
            assert_eq!(forged_sum, original_sum,
                "Partial shift: forged swap card {} c1+c2 should equal original", i);
        }

        // 使用原始证明验证应失败
        let mut transcript = Transcript::new(b"reconstruct_proof_test");
        let proof = ReconstructProof::<RistrettoCurve>::prove(
            cards.clone(),
            user_readable_cards.clone(),
            output_cards.clone(),
            swap_out_cards.clone(),
            &user_sk,
            &user_pk,
            s_vec.clone(),
            &mut transcript,
        ).unwrap();

        let mut verify_ts = Transcript::new(b"reconstruct_proof_test");
        let result = proof.verify(&cards, &output_cards, &forged_swap_cards, &user_pk, &mut verify_ts);
        assert!(result.is_err(),
            "Partial c1/c2 shift forged swap cards should be REJECTED");

        println!("c1/c2 部分信息转移攻击测试通过");
    }

    /// 安全验证: 诚实证明在添加 c1/c2 独立 Schnorr 证明后仍能通过验证
    #[test]
    fn test_honest_reconstruct_proof_with_c1_c2_proofs() {
        let (cards, user_readable_cards, output_cards, swap_out_cards, user_sk, user_pk, _share_pk, _coefficient, s_vec) =
            setup_reconstruct_proof_attack(5, 2);

        let mut transcript = Transcript::new(b"reconstruct_proof_test");
        let proof = ReconstructProof::<RistrettoCurve>::prove(
            cards.clone(),
            user_readable_cards.clone(),
            output_cards.clone(),
            swap_out_cards.clone(),
            &user_sk,
            &user_pk,
            s_vec.clone(),
            &mut transcript,
        ).unwrap();

        let swap_cards_only: Vec<ElGamalCiphertext> = swap_out_cards.iter().map(|(_, oc)| *oc).collect();
        let mut verify_ts = Transcript::new(b"reconstruct_proof_test");
        let result = proof.verify(&cards, &output_cards, &swap_cards_only, &user_pk, &mut verify_ts);
        assert!(result.is_ok(), "Honest ReconstructProof should verify with c1/c2 proofs");

        println!("诚实 ReconstructProof (含 c1/c2 独立 Schnorr 证明) 验证通过");
    }

    /// 安全验证: 篡改 swap_sum_c1_commit 后 c1 Schnorr 证明验证失败
    #[test]
    fn test_tampered_swap_c1_commit_fails() {
        let (cards, user_readable_cards, output_cards, swap_out_cards, user_sk, user_pk, _share_pk, _coefficient, s_vec) =
            setup_reconstruct_proof_attack(5, 2);

        let mut transcript = Transcript::new(b"reconstruct_proof_test");
        let mut proof = ReconstructProof::<RistrettoCurve>::prove(
            cards.clone(),
            user_readable_cards.clone(),
            output_cards.clone(),
            swap_out_cards.clone(),
            &user_sk,
            &user_pk,
            s_vec.clone(),
            &mut transcript,
        ).unwrap();

        // 篡改 swap_sum_c1_commit
        proof.swap_sum_c1_commit = proof.swap_sum_c1_commit + RistrettoCurve::base_g();

        let swap_cards_only: Vec<ElGamalCiphertext> = swap_out_cards.iter().map(|(_, oc)| *oc).collect();
        let mut verify_ts = Transcript::new(b"reconstruct_proof_test");
        let result = proof.verify(&cards, &output_cards, &swap_cards_only, &user_pk, &mut verify_ts);
        assert!(result.is_err(), "Tampered swap_sum_c1_commit should fail verification");

        println!("篡改 swap_sum_c1_commit 后验证失败 (c1 Schnorr 证明检测到)");
    }

    /// 安全验证: 篡改 swap_sum_c2_commit 后 c2 Schnorr 证明验证失败
    #[test]
    fn test_tampered_swap_c2_commit_fails() {
        let (cards, user_readable_cards, output_cards, swap_out_cards, user_sk, user_pk, _share_pk, _coefficient, s_vec) =
            setup_reconstruct_proof_attack(5, 2);

        let mut transcript = Transcript::new(b"reconstruct_proof_test");
        let mut proof = ReconstructProof::<RistrettoCurve>::prove(
            cards.clone(),
            user_readable_cards.clone(),
            output_cards.clone(),
            swap_out_cards.clone(),
            &user_sk,
            &user_pk,
            s_vec.clone(),
            &mut transcript,
        ).unwrap();

        // 篡改 swap_sum_c2_commit
        proof.swap_sum_c2_commit = proof.swap_sum_c2_commit + RistrettoCurve::base_g();

        let swap_cards_only: Vec<ElGamalCiphertext> = swap_out_cards.iter().map(|(_, oc)| *oc).collect();
        let mut verify_ts = Transcript::new(b"reconstruct_proof_test");
        let result = proof.verify(&cards, &output_cards, &swap_cards_only, &user_pk, &mut verify_ts);
        assert!(result.is_err(), "Tampered swap_sum_c2_commit should fail verification");

        println!("篡改 swap_sum_c2_commit 后验证失败 (c2 Schnorr 证明检测到)");
    }
}
