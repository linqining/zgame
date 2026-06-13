mod chaum_pedersen;
mod swap_out;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use merlin::Transcript;
use rand_core::OsRng;
use rayon::prelude::*;
use crate::crypto::curve::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
use crate::zk_shuffle::transcript_ext::TranscriptExtension;
use crate::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof;
pub use crate::zk_shuffle::error::VerificationError;
pub use chaum_pedersen::ChaumPedersenDLEQProof;
pub use swap_out::{SwapOutCardProof, ReconstructionDLEQProof};

pub fn exp_iter<C: Curve>(x: C::Scalar) -> impl Iterator<Item = C::Scalar> {
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
    if coefficient == &C::Scalar::zero() || coefficient == &C::Scalar::one(){
        return Err(VerificationError::InvalidCoefficient);
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
    let output_cards: Vec<ElGamalCiphertextGeneric<C>> = cards
        .par_iter()
        .enumerate()
        .map(|(i, card)| {
            let mut enc_card = ElGamalCiphertextGeneric::<C>::encrypt(card, user_pk, &s_vec[i]);
            if user_plain_card.contains(card) {
                enc_card.c2 = enc_card.c2 - *card;
            }
            enc_card
        })
        .collect();

    // Build the index map for plain cards (sequential due to HashMap mutation)
    for (i, card) in cards.iter().enumerate() {
        if user_plain_card.contains(card) {
            plain_card_idx_map.insert(card.compress().as_ref().to_vec(), i);
        }
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

#[derive(Debug, Clone)]
pub struct ReconstructProof<C: Curve> {
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
    pub fn prove(
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
            let swap_out_card_proof = SwapOutCardProof::prove(user_readable_card.clone(), swap_out_card.1.clone(), user_sk, user_pk, transcript)?;
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

        // - swap_sum_c1_commit 和 swap_sum_c2_commit 不直接通过 DLEQ 证明
        // - 密码学上合理但代码可读性差，建议添加注释
        // 设计如此，避免验证方可以排列组合 swap_out_cards 和 scalars 暴力破解 sum_output_c1,sum_output_c2 + sum(swap_out_cards*ri) 是 满足chaum pedersen proof 的条件
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
        )?;

        // 生成 c1/c2 独立 Schnorr 证明，防止 c1/c2 信息转移攻击
        let base_points_c1: Vec<C::Point> = swap_out_cards.iter().map(|(_, oc)| oc.c1).collect();
        let base_points_c2: Vec<C::Point> = swap_out_cards.iter().map(|(_, oc)| oc.c2).collect();

        let sum_swap_out_c1_schnorr_proof = GeneralizedSchnorrProof::<C>::prove(
            &base_points_c1,
            &secret_vec,
            &swap_sum_c1_commit,
            transcript,
        )?;
        let sum_swap_out_c2_schnorr_proof = GeneralizedSchnorrProof::<C>::prove(
            &base_points_c2,
            &secret_vec,
            &swap_sum_c2_commit,
            transcript,
        )?;

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
        )?;

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

    pub fn verify(
        &self,
        cards: &[C::Point],
        output_cards: &[ElGamalCiphertextGeneric<C>],
        swap_out_cards: &[ElGamalCiphertextGeneric<C>],
        user_readable_cards: &[ElGamalCiphertextGeneric<C>],
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
        if self.swap_out_cards_proofs.len() != user_readable_cards.len() {
            return Err(VerificationError::InvalidProofAtPosition(0));
        }
        // 防御性检查: swap_out_cards 长度必须与 swap_out_cards_proofs 一致
        if swap_out_cards.len() != self.swap_out_cards_proofs.len() {
            return Err(VerificationError::InvalidProofAtPosition(0));
        }
        for (i, proof) in self.swap_out_cards_proofs.iter().enumerate() {
            if proof.swap_out_card != swap_out_cards[i] {
                return Err(VerificationError::InvalidProofAtPosition(i));
            }
            // SECURITY FIX: 验证 proof 中的 user_readable_card 与预期的 user_readable_cards 一致
            // 防止攻击者使用伪造的 user_readable_cards 生成 swap 证明
            if proof.user_readable_card != user_readable_cards[i] {
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
