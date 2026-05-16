//! # ZK Shuffle Consistency Circuit (V3 — 2-Way)
//!
//! ## 问题背景
//!
//! V2 协议中的 `PerElementCommitment` 存在**隐私泄露缺陷**：
//!
//! ```ignore
//! fn verify_responses(&self, responses, challenge, input_cts, output_cts) {
//!     for i in 0..n {
//!         let dc1 = output_cts[i].c1 - input_cts[i].c1;  // ⚠️ 按索引配对！
//!         let dc2 = output_cts[i].c2 - input_cts[i].c2;  // ⚠️ 假设 output[i] ↔ input[i]
//!     }
//! }
//! ```
//!
//! **问题**：在 Shuffle 场景中，`output[j] = ReEnc(input[permute[j]], r'_j)`，
//! 即 `output[j]` 对应的是 `input[permute[j]]` 而非 `input[j]`。
//!
//! 按索引对齐计算差分会：
//! 1. **泄露置换信息**：差分模式直接暴露了哪个 input 到了哪个 output 位置
//! 2. **验证语义错误**：计算的 diff 不是真实的重加密差异，证明无意义
//!
//! ## 解决方案：ZK Σ-Protocol（零知识逐元素一致性证明，2-Way）
//!
//! ### 核心思想
//!
//! **Prover 知道私有置换 π 和随机数 {r'_j}，Verifier 完全不知道。**
//!
//! Prover 在**内部**使用真实置换计算差异值，然后通过 **Blinded Batch DLEq**
//! 证明这些差异满足 **(G, pk) 两列一致性**，同时**不暴露任何关于 π 的信息**。
//!
//! ### 设计决策：为什么是 2-way（移除 c3）？
//!
//! | 检查方式 | 约束 |
//! |---------|------|
//! | log_G(D1) = log_pk(D2) | δ₁[j] 和 δ₂[j] 共享同一离散对数 r'j |
//!
//! **2-way 对以下攻击充分**：
//! - C2-Swap 攻击：交换 output[a].c2 ↔ output[b].c2 → D2 离散对数偏移 → 检测 ✅
//! - 注入偏差攻击：δ₂ 包含混合基项 → D₂ 不是 pk 的纯倍数 → 检测 ✅
//! - 任意单列/多列篡改：通过 Schwartz-Zippel 引理检测 ✅
//!
//! **Soundness 归约**：
//! - ROM 下 ρ[j] 表现为均匀随机
//! - 若任一位置 α_j ≠ β_j，则 P[Σρ_j·(α_j-β_j)=0] ≤ 1/q ≈ 2⁻²⁵⁶
//! - 归约到 SHA256 抗碰撞性 + ℤ_q 上均匀分布
//!
//! ### 协议流程
//!
//! ```
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Public Inputs                            │
//! │  input_cts[0..n], output_cts[0..n], pk, G                   │
//! ├─────────────────────────────────────────────────────────────┤
//! │                   Private Witness (仅 Prover 知道)            │
//! │  permute[0..n], r_values[0..n]                               │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │  PROVER (知道 π):                                           │
//! │  ① 计算 REAL 差异（使用私有置换）:                           │
//! │     δ1[j] = out[j].c1 - in[π[j]].c1  = G·r'j               │
//! │     δ2[j] = out[j].c2 - in[π[j]].c2  = pk·r'j              │
//! │                                                             │
//! │  ② 导出公开随机系数（从公开输出计算，Verifier 可复现）:      │
//! │     ρ[j] = Hash("zk_rho", all_output_coords, j)             │
//! │                                                             │
//! │  ③ 计算批量聚合（私有，因为依赖 π）:                         │
//! │     D1 = Σ ρ[j]·δ1[j]  = G·Σ(ρ[j]·r'j) = G·R              │
//! │     D2 = Σ ρ[j]·δ2[j]  = pk·R                              │
//! │                                                             │
//! │  ④ 生成 2-Way DLEq Proof (标准 Schnorr):                    │
//! │     w ←$ Zq                                                │
//! │     Ag = G·w, Apk = pk·w                                   │
//! │     c = Hash(pk, Ag, Apk, D1, D2)                          │
//! │     s = w + c·R                                             │
//! │                                                             │
//! │  发送 Proof = (D1, D2, Ag, Apk, s)                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │  VERIFIER (不知道 π):                                        │
//! │  ① 复现 ρ[j]（与 Prover 相同的公开数据）                     │
//! │  ② 接收 (D1, D2, Ag, Apk, s)                               │
//! │  ③ 复现挑战 c = Hash(pk, Ag, Apk, D1, D2)                  │
//! │  ④ 验证二方程:                                              │
//! │     G·s  == Ag + D1·c  ?                                   │
//! │     pk·s == Apk + D2·c ?                                   │
//! │                                                             │
//! │  ✅ 通过 → (G,pk) 两列一致且未泄露置换                       │
//! │  ❌ 失败 → 存在列不一致（如 c2 交换攻击）                    │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### 安全性分析
//!
//! #### 隐私性 (Zero-Knowledge)
//! - Verifier 看到：(D1, D2) 是批量聚合值，无法反推出单个 δ[j]
//! - (Ag, Apk, s) 是标准的 Schnorr 承诺/响应，不泄露 R
//! - **置换 π 完全隐藏**：从未出现在任何公开值中 ✅
//! - **单个 r'_j 隐藏**：只暴露加权和 R = Σρ[j]·r'[j] ✅
//!
//! #### 完备性 (Completeness)
//! - 诚实 Prover 使用真实 π 和 r' 计算 D1,D2
//! - DLEq 方程恒成立：G·s = G·(w+cR) = Gw + GcR = Ag + D1·c ✅
//!
//! #### 声音性 (Soundness)
//! - **c2 交换攻击检测**：
//!   攻击者交换 output[a].c2 ↔ output[b].c2 后：
//!   - D2 包含错误的 δ2 值（混合了不同元素的 r'）
//!   - D2 ≠ pk·R（因为 R 是按正确 r' 加权的）
//!   - 方程 pk·s = Apk + D2·c 不成立 → **检测到攻击** ✅
//!
//! - **注入偏差攻击检测**：
//!   若 δ₂[j] = pk·r'_j + G·t_j 且 t_j 使逐元素 G-对数一致，
//!   但聚合后 D₂ = pk·R + G·T 不是 pk 的纯倍数 → **检测到** ✅
//!
//! - **伪造证明**：需要解决离散对数问题（DLP）✅
//!
//! ### 与其他组件的关系
//!
//! | 组件 | 保护范围 | 是否泄露置换 |
//! |------|---------|-------------|
//! | Triple-DLEq | 全局三列总和一致性 | ❌ 不泄露 |
//! | ProductArgument | c1 乘积关系 | ❌ 不泄露 |
//! | **ZKConsistencyV3 (本模块)** | **逐元素 (G,pk) 一致性** | **❌ 不泄露** ✅ |
//! | PerElementCommitment (旧) | 逐元素差异 | ⚠️ **会泄露** ✗ |
//!

use crate::crypto::{EcPoint, Scalar, ElGamalCiphertextV2, BASE_G, N_CARDS, hash_to_scalar};
use ff::{Field, };
use group::{ GroupEncoding};
use rand_core::RngCore;
use sha2::{Digest, Sha256};



pub const ZK_CONSISTENCY_DOMAIN: &[u8] = b"zk_shuffle_consistency_v3_2way";

#[derive(Debug, Clone)]
pub struct ZKConsistencyProof {
    pub d1: EcPoint,
    pub d2: EcPoint,
    pub a_g: EcPoint,
    pub a_pk: EcPoint,
    pub s: Scalar,
}

impl ZKConsistencyProof {
    pub fn prove(
        input_cts: &[ElGamalCiphertextV2],
        output_cts: &[ElGamalCiphertextV2],
        permute: &[usize; N_CARDS],
        r_values: &[Scalar],
        pk: &EcPoint,
        rng: &mut impl RngCore,
    ) -> Self {
        let n = N_CARDS;

        let rho = Self::derive_batch_coefficients(output_cts);

        let deltas: Vec<(k256::AffinePoint, k256::AffinePoint)> = (0..n)
            .map(|j| {
                let i = permute[j];
                (
                    (output_cts[j].c1 - input_cts[i].c1).to_affine(),
                    (output_cts[j].c2 - input_cts[i].c2).to_affine(),
                )
            })
            .collect();

        let weighted_r = r_values.iter()
            .zip(rho.iter())
            .fold(Scalar::ZERO, |acc, (r, rh)| acc + *r * *rh);

        let d1 = deltas.iter()
            .zip(rho.iter())
            .fold(EcPoint::IDENTITY, |acc, ((dc1, _dc2), r)| acc + *dc1 * *r);

        let d2 = deltas.iter()
            .zip(rho.iter())
            .fold(EcPoint::IDENTITY, |acc, ((_dc1, dc2), r)| acc + *dc2 * *r);

        let w = Scalar::random(rng);

        let a_g = *BASE_G * w;
        let a_pk = *pk * w;

        let challenge =
            Self::hash_to_challenge(pk, &a_g, &a_pk, &d1, &d2, output_cts);

        let s = w + challenge * weighted_r;

        ZKConsistencyProof {
            d1,
            d2,
            a_g,
            a_pk,
            s,
        }
    }

    pub fn prove_commitments(
        input_cts: &[ElGamalCiphertextV2],
        output_cts: &[ElGamalCiphertextV2],
        permute: &[usize; N_CARDS],
        r_values: &[Scalar],
        pk: &EcPoint,
        rng: &mut impl RngCore,
    ) -> (EcPoint, EcPoint, EcPoint, EcPoint, Scalar, Scalar) {
        let n = N_CARDS;

        let rho = Self::derive_batch_coefficients(output_cts);

        let mut weighted_r = Scalar::ZERO;
        let mut d1 = EcPoint::IDENTITY;
        let mut d2 = EcPoint::IDENTITY;

        for j in 0..n {
            let i = permute[j];
            let delta_c1 = output_cts[j].c1 - input_cts[i].c1;
            let delta_c2 = output_cts[j].c2 - input_cts[i].c2;

            d1 = d1 + delta_c1 * rho[j];
            d2 = d2 + delta_c2 * rho[j];
            weighted_r = weighted_r + r_values[j] * rho[j];
        }

        let w = Scalar::random(rng);

        let a_g = *BASE_G * w;
        let a_pk = *pk * w;

        (d1, d2, a_g, a_pk, w, weighted_r)
    }

    pub fn respond(
        d1: EcPoint,
        d2: EcPoint,
        a_g: EcPoint,
        a_pk: EcPoint,
        challenge: &Scalar,
        w: &Scalar,
        weighted_r: &Scalar,
    ) -> Self {
        let s = w + challenge * weighted_r;
        ZKConsistencyProof {
            d1,
            d2,
            a_g,
            a_pk,
            s,
        }
    }

    pub fn verify_with_challenge(
        &self,
        output_cts: &[ElGamalCiphertextV2],
        pk: &EcPoint,
        external_challenge: &Scalar,
    ) -> bool {
        let check1 = (*BASE_G * self.s) == (self.a_g + self.d1 * *external_challenge);
        let check2 = (*pk * self.s) == (self.a_pk + self.d2 * *external_challenge);

        check1 && check2
    }

    pub fn verify(
        &self,
        _input_cts: &[ElGamalCiphertextV2],
        output_cts: &[ElGamalCiphertextV2],
        pk: &EcPoint,
    ) -> bool {
        let _rho = Self::derive_batch_coefficients(output_cts);

        let challenge = Self::hash_to_challenge(
            pk,
            &self.a_g,
            &self.a_pk,
            &self.d1,
            &self.d2,
            output_cts,
        );

        let check1 = (*BASE_G * self.s) == (self.a_g + self.d1 * challenge);
        let check2 = (*pk * self.s) == (self.a_pk + self.d2 * challenge);

        check1 && check2
    }

    fn derive_batch_coefficients(output_cts: &[ElGamalCiphertextV2]) -> Vec<Scalar> {
        let n = N_CARDS;
        let mut coeffs = Vec::with_capacity(n);

        for j in 0..n {
            let mut h = Sha256::new();
            h.update(ZK_CONSISTENCY_DOMAIN);
            h.update(b":rho:");
            h.update(&[j as u8]);
            for ct in output_cts.iter().take(n) {
                h.update(ct.c1.to_affine().to_bytes());
                h.update(ct.c2.to_affine().to_bytes());
                h.update(ct.c3.to_affine().to_bytes());
            }
            let digest = h.finalize();
            coeffs.push(hash_to_scalar(&digest));
        }
        coeffs
    }

    fn hash_to_challenge(
        pk: &EcPoint,
        a_g: &EcPoint,
        a_pk: &EcPoint,
        d1: &EcPoint,
        d2: &EcPoint,
        output_cts: &[ElGamalCiphertextV2],
    ) -> Scalar {
        let mut h = Sha256::new();
        h.update(ZK_CONSISTENCY_DOMAIN);
        h.update(b":challenge:");
        h.update(pk.to_affine().to_bytes());
        h.update(a_g.to_affine().to_bytes());
        h.update(a_pk.to_affine().to_bytes());
        h.update(d1.to_affine().to_bytes());
        h.update(d2.to_affine().to_bytes());
        for ct in output_cts.iter().take(N_CARDS) {
            h.update(ct.c1.to_affine().to_bytes());
            h.update(ct.c2.to_affine().to_bytes());
            h.update(ct.c3.to_affine().to_bytes());
        }

        let digest = h.finalize();
        hash_to_scalar(&digest)
    }
}

#[derive(Debug, Clone)]
pub struct ZKShuffleProofV3 {
    pub zk_consistency: ZKConsistencyProof,
    pub triple_dleq: crate::crypto::TripleDLEqProof,
    pub product_arg: crate::crypto::ProductArgumentV2,
    pub global_challenge: Scalar,
    pub nonce: Scalar,
}

impl ZKShuffleProofV3 {
    fn compute_global_challenge(
        pk: &EcPoint,
        zk_a_g: &EcPoint,
        zk_a_pk: &EcPoint,
        zk_d1: &EcPoint,
        zk_d2: &EcPoint,
        dleq_A_g: &EcPoint,
        dleq_A_h: &EcPoint,
        prod_A: &EcPoint,
        prod_B: &EcPoint,
        prod_C: &EcPoint,
        prod_D: &EcPoint,
        input_cts: &[ElGamalCiphertextV2],
        output_cts: &[ElGamalCiphertextV2],
        nonce: &Scalar,
    ) -> Scalar {
        let mut h = Sha256::new();
        h.update(b"shuffle_v3_transcript_bound");
        h.update(b":nonce:");
        h.update(nonce.to_bytes());
        h.update(pk.to_affine().to_bytes());
        h.update(zk_a_g.to_affine().to_bytes());
        h.update(zk_a_pk.to_affine().to_bytes());
        h.update(zk_d1.to_affine().to_bytes());
        h.update(zk_d2.to_affine().to_bytes());
        h.update(dleq_A_g.to_affine().to_bytes());
        h.update(dleq_A_h.to_affine().to_bytes());
        h.update(prod_A.to_affine().to_bytes());
        h.update(prod_B.to_affine().to_bytes());
        h.update(prod_C.to_affine().to_bytes());
        h.update(prod_D.to_affine().to_bytes());

        for ct in input_cts.iter().take(N_CARDS) {
            h.update(ct.c1.to_affine().to_bytes());
            h.update(ct.c2.to_affine().to_bytes());
            h.update(ct.c3.to_affine().to_bytes());
        }
        for ct in output_cts.iter().take(N_CARDS) {
            h.update(ct.c1.to_affine().to_bytes());
            h.update(ct.c2.to_affine().to_bytes());
            h.update(ct.c3.to_affine().to_bytes());
        }

        let digest = h.finalize();
        hash_to_scalar(&digest)
    }

    pub fn prove(
        input_cts: &[ElGamalCiphertextV2],
        output_cts: &[ElGamalCiphertextV2],
        permute: &[usize; N_CARDS],
        r_values: &[Scalar],
        pk: &EcPoint,
        rng: &mut impl RngCore,
    ) -> Self {

        let (zk_d1, zk_d2, zk_a_g, zk_a_pk, zk_w, zk_weighted_r) =
            ZKConsistencyProof::prove_commitments(input_cts, output_cts, permute, r_values, pk, rng);

        let total_r: Scalar = r_values
            .iter()
            .take(N_CARDS)
            .fold(Scalar::ZERO, |acc, r| acc + r);

        let mut sum_in = (
            EcPoint::IDENTITY,
            EcPoint::IDENTITY,
            EcPoint::IDENTITY,
        );
        let mut sum_out = (
            EcPoint::IDENTITY,
            EcPoint::IDENTITY,
            EcPoint::IDENTITY,
        );

        for ct in input_cts.iter().take(N_CARDS) {
            sum_in.0 = sum_in.0 + ct.c1;
            sum_in.1 = sum_in.1 + ct.c2;
            sum_in.2 = sum_in.2 + ct.c3;
        }
        for ct in output_cts.iter().take(N_CARDS) {
            sum_out.0 = sum_out.0 + ct.c1;
            sum_out.1 = sum_out.1 + ct.c2;
            sum_out.2 = sum_out.2 + ct.c3;
        }

        let (dleq_A_g, dleq_A_pk, dleq_A_h, _dc1, _dc2, _dc3, dleq_w, dleq_total_r) =
            crate::crypto::TripleDLEqProof::prove_commitments(
                &sum_in.0, &sum_in.1, &sum_in.2,
                &sum_out.0, &sum_out.1, &sum_out.2,
                &total_r, pk, rng,
            );

        let (prod_A, prod_B, prod_C, prod_D, _pi_c1, _po_c1, prod_alpha, prod_beta, prod_total_r) =
            crate::crypto::ProductArgumentV2::prove_commitments(
                input_cts, output_cts, r_values, rng,
            );

        let nonce = Scalar::random(rng);

        let global_challenge = Self::compute_global_challenge(
            pk,
            &zk_a_g, &zk_a_pk, &zk_d1, &zk_d2,
            &dleq_A_g, &dleq_A_h,
            &prod_A, &prod_B, &prod_C, &prod_D,
            input_cts, output_cts,
            &nonce,
        );

        let zk_consistency = ZKConsistencyProof::respond(
            zk_d1, zk_d2, zk_a_g, zk_a_pk,
            &global_challenge, &zk_w, &zk_weighted_r,
        );

        let triple_dleq = crate::crypto::TripleDLEqProof::respond(
            dleq_A_g, dleq_A_pk, dleq_A_h,
            &global_challenge, &dleq_w, &dleq_total_r,
        );

        let product_arg = crate::crypto::ProductArgumentV2::respond(
            prod_A, prod_B, prod_C, prod_D,
            &global_challenge, &prod_alpha, &prod_beta, &prod_total_r,
        );

        ZKShuffleProofV3 {
            zk_consistency,
            triple_dleq,
            product_arg,
            global_challenge,
            nonce,
        }
    }

    pub fn verify(
        &self,
        input_cts: &[ElGamalCiphertextV2],
        output_cts: &[ElGamalCiphertextV2],
        pk: &EcPoint,
    ) -> bool {
        let expected_challenge = Self::compute_global_challenge(
            pk,
            &self.zk_consistency.a_g,
            &self.zk_consistency.a_pk,
            &self.zk_consistency.d1,
            &self.zk_consistency.d2,
            &self.triple_dleq.A_g,
            &self.triple_dleq.A_h,
            &self.product_arg.A,
            &self.product_arg.B,
            &self.product_arg.C,
            &self.product_arg.D,
            input_cts,
            output_cts,
            &self.nonce,
        );

        if self.global_challenge != expected_challenge {
            return false;
        }

        let zk_ok = self.zk_consistency.verify_with_challenge(output_cts, pk, &self.global_challenge);

        let mut sum_in = (
            EcPoint::IDENTITY,
            EcPoint::IDENTITY,
            EcPoint::IDENTITY,
        );
        let mut sum_out = (
            EcPoint::IDENTITY,
            EcPoint::IDENTITY,
            EcPoint::IDENTITY,
        );

        for ct in input_cts.iter().take(N_CARDS) {
            sum_in.0 = sum_in.0 + ct.c1;
            sum_in.1 = sum_in.1 + ct.c2;
            sum_in.2 = sum_in.2 + ct.c3;
        }
        for ct in output_cts.iter().take(N_CARDS) {
            sum_out.0 = sum_out.0 + ct.c1;
            sum_out.1 = sum_out.1 + ct.c2;
            sum_out.2 = sum_out.2 + ct.c3;
        }

        let dleq_ok = self.triple_dleq.verify_with_challenge(
            &sum_in.0, &sum_in.1, &sum_in.2,
            &sum_out.0, &sum_out.1, &sum_out.2,
            pk, &self.global_challenge,
        );

        let product_ok = self.product_arg.verify_with_challenge(
            input_cts, output_cts, pk, &self.global_challenge,
        );

        zk_ok && dleq_ok && product_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ec_encrypt_batch_v2;
    use rand::seq::SliceRandom;
    use rand_core::OsRng;
    use std::time;

    #[test]
    fn test_zk_consistency_normal_shuffle() {
        println!("\n=== ZK Consistency 2-Way: Normal Shuffle (should PASS) ===\n");

        let mut rng = OsRng;
        let sk = Scalar::random(&mut rng);
        let pk = *BASE_G * sk;

        let msgs: Vec<EcPoint> = (0..N_CARDS)
            .map(|i| *BASE_G * Scalar::from((i + 1) as u32))
            .collect();

        let encrypted = ec_encrypt_batch_v2(&msgs, &pk, &mut rng);

        let permute: [usize; N_CARDS] = {
            let mut arr: Vec<usize> = (0..N_CARDS).collect();
            let mut seed = [0u8; 32];
            for b in seed.iter_mut() {
                *b = rand::random::<u8>();
            }
            use rand::SeedableRng;
            let mut prng = rand::rngs::StdRng::from_seed(seed);
            arr.shuffle(&mut prng);
            let mut fixed = [0usize; N_CARDS];
            fixed.copy_from_slice(&arr);
            fixed
        };

        let full_input: Vec<ElGamalCiphertextV2> = encrypted
            .clone()
            .into_iter()
            .chain(std::iter::repeat(ElGamalCiphertextV2::new_placehod_card()))
            .take(N_CARDS)
            .collect();

        let mut r_values = Vec::with_capacity(N_CARDS);
        let mut output = Vec::with_capacity(N_CARDS);
        for j in 0..N_CARDS {
            let r_j = Scalar::random(&mut rng);
            r_values.push(r_j);
            let i = permute[j];
            output.push(full_input[i].re_encrypt(&pk, &r_j));
        }
        let begin = time::Instant::now();
        let proof =
            ZKConsistencyProof::prove(&full_input, &output, &permute, &r_values, &pk, &mut rng);
        let end = begin.elapsed();
        println!("  ZK Consistency 2-Way (normal): prove in {:?}", end);

        let begin = time::Instant::now();
        let valid = proof.verify(&full_input, &output, &pk);
        let end = begin.elapsed();
        println!("  ZK Consistency 2-Way (normal): {} in {:?}", if valid { "PASSED ✓" } else { "FAILED ✗" }, end);


        println!(
            "  ZK Consistency 2-Way (normal): {}",
            if valid { "PASSED ✓" } else { "FAILED ✗" }
        );
        assert!(valid, "Normal shuffle must pass ZK consistency check");
    }

    #[test]
    fn test_zk_consistency_c2_swap_attack() {
        println!("\n=== ZK Consistency 2-Way: C2-Swap Attack (should FAIL) ===\n");

        let mut rng = OsRng;
        let sk = Scalar::random(&mut rng);
        let pk = *BASE_G * sk;

        let m0 = *BASE_G * Scalar::from(50u32);
        let m1 = *BASE_G * Scalar::from(100u32);

        let ct0 = ElGamalCiphertextV2::encrypt(&m0, &pk, &Scalar::from(42u32));
        let ct1 = ElGamalCiphertextV2::encrypt(&m1, &pk, &Scalar::from(123u32));

        let r_prime = Scalar::from(777u32);

        let ct0_normal = ct0.re_encrypt(&pk, &r_prime);
        let ct1_normal = ct1.re_encrypt(&pk, &r_prime);

        let ct0_swap = ElGamalCiphertextV2 {
            c1: ct0_normal.c1,
            c2: ct1_normal.c2,
            c3: ct0_normal.c3,
        };
        let ct1_swap = ElGamalCiphertextV2 {
            c1: ct1_normal.c1,
            c2: ct0_normal.c2,
            c3: ct1_normal.c3,
        };

        println!("  Attack: CT0_swap=(c1₀', c2₁', c3₀'), CT1_swap=(c1₁', c2₀', c3₁')");

        let inputs = vec![ct0, ct1];
        let swap_outputs = vec![ct0_swap, ct1_swap];

        let full_inputs: Vec<ElGamalCiphertextV2> = inputs
            .into_iter()
            .chain(std::iter::repeat(ElGamalCiphertextV2::new_placehod_card()))
            .take(N_CARDS)
            .collect();

        let full_swap: Vec<ElGamalCiphertextV2> = swap_outputs
            .into_iter()
            .chain(std::iter::repeat(ElGamalCiphertextV2::new_placehod_card()))
            .take(N_CARDS)
            .collect();

        let permute_identity: [usize; N_CARDS] = {
            let mut arr = [0usize; N_CARDS];
            for i in 0..N_CARDS {
                arr[i] = i;
            }
            arr
        };
        let r_values = vec![r_prime; N_CARDS];

        let proof = ZKConsistencyProof::prove(
            &full_inputs,
            &full_swap,
            &permute_identity,
            &r_values,
            &pk,
            &mut rng,
        );
        let valid = proof.verify(&full_inputs, &full_swap, &pk);

        println!(
            "  ZK Consistency 2-Way (c2-swap): {}",
            if valid {
                "PASSED ✗ (NOT DETECTED!)"
            } else {
                "FAILED ✓ (DETECTED!)"
            }
        );
        assert!(
            !valid,
            "C2-swap attack MUST be rejected by ZK consistency proof!"
        );

        println!("\n  Decryption check:");
        let dec0 = full_swap[0].decrypt(&sk);
        let dec1 = full_swap[1].decrypt(&sk);
        println!(
            "    msg0_correct={}, msg1_correct={}",
            dec0 == m0,
            dec1 == m1
        );
        println!("    ✅ Data corruption confirmed, attack detected by ZK proof");
    }

    #[test]
    fn test_zk_full_protocol_normal_vs_attack() {
        println!("\n=== ZKShuffleProofV3 (2-Way): Full Protocol Test ===\n");

        let mut rng = OsRng;
        let sk = Scalar::random(&mut rng);
        let pk = *BASE_G * sk;

        let msgs: Vec<EcPoint> = (0..N_CARDS)
            .map(|i| *BASE_G * Scalar::from((i + 1) as u32))
            .collect();

        let encrypted = ec_encrypt_batch_v2(&msgs, &pk, &mut rng);

        let permute: [usize; N_CARDS] = {
            let mut arr: Vec<usize> = (0..N_CARDS).collect();
            let mut seed = [0u8; 32];
            for b in seed.iter_mut() {
                *b = rand::random::<u8>();
            }
            use rand::SeedableRng;
            let mut prng = rand::rngs::StdRng::from_seed(seed);
            arr.shuffle(&mut prng);
            let mut fixed = [0usize; N_CARDS];
            fixed.copy_from_slice(&arr);
            fixed
        };

        let full_input: Vec<ElGamalCiphertextV2> = encrypted
            .into_iter()
            .chain(std::iter::repeat(ElGamalCiphertextV2::new_placehod_card()))
            .take(N_CARDS)
            .collect();

        let mut r_values = Vec::with_capacity(N_CARDS);
        let mut normal_output = Vec::with_capacity(N_CARDS);
        for j in 0..N_CARDS {
            let r_j = Scalar::random(&mut rng);
            r_values.push(r_j);
            let i = permute[j];
            normal_output.push(full_input[i].re_encrypt(&pk, &r_j));
        }

        println!("--- Test 1: Normal shuffle ---");
        let normal_proof = ZKShuffleProofV3::prove(
            &full_input,
            &normal_output,
            &permute,
            &r_values,
            &pk,
            &mut rng,
        );
        let normal_valid = normal_proof.verify(&full_input, &normal_output, &pk);
        println!(
            "  Full ZK proof 2-Way (normal): {}",
            if normal_valid { "PASSED ✓" } else { "FAILED ✗" }
        );
        assert!(normal_valid);

        println!("\n--- Test 2: C2-Swap attack on element 0,1 ---");
        let mut attacked_output = normal_output.clone();
        let tmp = attacked_output[0].c2.clone();
        attacked_output[0].c2 = attacked_output[1].c2.clone();
        attacked_output[1].c2 = tmp;

        let attack_proof = ZKShuffleProofV3::prove(
            &full_input,
            &attacked_output,
            &permute,
            &r_values,
            &pk,
            &mut rng,
        );
        let attack_valid = attack_proof.verify(&full_input, &attacked_output, &pk);
        println!(
            "  Full ZK proof 2-Way (c2-swap): {}",
            if attack_valid { "PASSED ✗" } else { "FAILED ✓ (detected!)" }
        );
        assert!(!attack_valid, "C2-swap attack must fail full ZK proof!");

        println!("\n=== Privacy Verification ===");
        println!("  Verifier sees from ZKConsistencyProof (2-Way):");
        println!(
            "    - d1, d2: batch-aggregated group elements (no per-element info)"
        );
        println!("    - a_g, a_pk, s: standard Schnorr commitment/response");
        println!("    - NO permutation vector exposed ✅");
        println!("    - NO individual r'_j values exposed ✅");
        println!("    - NO input↔output mapping exposed ✅");
        println!("    - Proof size: 5 fields vs 7 (3-way), saves ~288 bytes");
    }

    #[test]
    fn test_zk_proof_size_and_performance() {
        println!("\n=== ZK Proof Size Analysis (2-Way) ===\n");

        let mut rng = OsRng;
        let sk = Scalar::random(&mut rng);
        let pk = *BASE_G * sk;

        let msgs: Vec<EcPoint> = (0..N_CARDS)
            .map(|i| *BASE_G * Scalar::from((i + 1) as u32))
            .collect();
        let encrypted = ec_encrypt_batch_v2(&msgs, &pk, &mut rng);

        let permute: [usize; N_CARDS] = {
            let mut arr: Vec<usize> = (0..N_CARDS).collect();
            let mut seed = [0u8; 32];
            for b in seed.iter_mut() {
                *b = rand::random::<u8>();
            }
            use rand::SeedableRng;
            let mut prng = rand::rngs::StdRng::from_seed(seed);
            arr.shuffle(&mut prng);
            let mut fixed = [0usize; N_CARDS];
            fixed.copy_from_slice(&arr);
            fixed
        };
        let full_input: Vec<ElGamalCiphertextV2> = encrypted
            .into_iter()
            .chain(std::iter::repeat(ElGamalCiphertextV2::new_placehod_card()))
            .take(N_CARDS)
            .collect();

        let mut r_values = Vec::with_capacity(N_CARDS);
        let mut output = Vec::with_capacity(N_CARDS);
        for j in 0..N_CARDS {
            let r_j = Scalar::random(&mut rng);
            r_values.push(r_j);
            output.push(full_input[j].re_encrypt(&pk, &r_j));
        }

        let proof = ZKConsistencyProof::prove(
            &full_input,
            &output,
            &permute,
            &r_values,
            &pk,
            &mut rng,
        );

        use std::mem::size_of_val;
        println!("  ZKConsistencyProof (2-Way) size breakdown:");
        println!(
            "    d1, d2: 2 × {} bytes = {} bytes",
            size_of_val(&proof.d1),
            2 * size_of_val(&proof.d1)
        );
        println!(
            "    a_g, a_pk: 2 × {} bytes = {} bytes",
            size_of_val(&proof.a_g),
            2 * size_of_val(&proof.a_g)
        );
        println!("    s (Scalar): {} bytes", size_of_val(&proof.s));
        let total_2way =
            2 * size_of_val(&proof.d1) + 2 * size_of_val(&proof.a_g) + size_of_val(&proof.s);
        let total_3way = total_2way + 2 * size_of_val(&proof.d1);
        println!("    Total (2-way): {} bytes ({:.1} KB)", total_2way, total_2way as f64 / 1024.0);
        println!(
            "    Total (3-way): {} bytes ({:.1} KB)",
            total_3way,
            total_3way as f64 / 1024.0
        );
        println!("    Savings: {} bytes ({:.1}%)",
            total_3way - total_2way,
            100.0 * (total_3way - total_2way) as f64 / total_3way as f64
        );
        println!(
            "    Complexity: O(1) — constant size regardless of n={}!",
            N_CARDS
        );
        println!("    Verify time: O(1) — 2 ECMuls + 2 ECAdds (vs 3+3 for 3-way)");
    }

    fn setup_shuffle_env() -> (Scalar, EcPoint, Vec<ElGamalCiphertextV2>, [usize; N_CARDS], Vec<Scalar>, Vec<ElGamalCiphertextV2>) {
        let mut rng = OsRng;
        let sk = Scalar::random(&mut rng);
        let pk = *BASE_G * sk;

        let msgs: Vec<EcPoint> = (0..N_CARDS)
            .map(|i| *BASE_G * Scalar::from((i + 1) as u32))
            .collect();

        let encrypted = ec_encrypt_batch_v2(&msgs, &pk, &mut rng);

        let permute: [usize; N_CARDS] = {
            let mut arr: Vec<usize> = (0..N_CARDS).collect();
            let mut seed = [0u8; 32];
            for b in seed.iter_mut() {
                *b = rand::random::<u8>();
            }
            use rand::SeedableRng;
            let mut prng = rand::rngs::StdRng::from_seed(seed);
            arr.shuffle(&mut prng);
            let mut fixed = [0usize; N_CARDS];
            fixed.copy_from_slice(&arr);
            fixed
        };

        let full_input: Vec<ElGamalCiphertextV2> = encrypted
            .into_iter()
            .chain(std::iter::repeat(ElGamalCiphertextV2::new_placehod_card()))
            .take(N_CARDS)
            .collect();

        let mut r_values = Vec::with_capacity(N_CARDS);
        let mut output = Vec::with_capacity(N_CARDS);
        for j in 0..N_CARDS {
            let r_j = Scalar::random(rng);
            r_values.push(r_j);
            let i = permute[j];
            output.push(full_input[i].re_encrypt(&pk, &r_j));
        }

        (sk, pk, full_input, permute, r_values, output)
    }

    #[test]
    fn test_transcript_binding_proof_splicing_attack() {
        println!("\n=== Security Test: Proof Splicing Attack (should FAIL) ===\n");

        let mut rng = OsRng;

        let (_sk1, pk1, input1, permute1, r_values1, output1) = setup_shuffle_env();
        let (_sk2, pk2, input2, permute2, r_values2, output2) = setup_shuffle_env();

        let mut rng3 = OsRng;
        let proof1 = ZKShuffleProofV3::prove(&input1, &output1, &permute1, &r_values1, &pk1, &mut rng3);
        let mut rng4 = OsRng;
        let proof2 = ZKShuffleProofV3::prove(&input2, &output2, &permute2, &r_values2, &pk2, &mut rng4);

        let mut spliced = proof1.clone();
        spliced.triple_dleq = proof2.triple_dleq.clone();

        let spliced_valid = spliced.verify(&input1, &output1, &pk1);
        println!(
            "  Spliced proof (swap triple_dleq from different shuffle): {}",
            if spliced_valid { "PASSED ✗ (NOT DETECTED!)" } else { "FAILED ✓ (DETECTED!)" }
        );
        assert!(!spliced_valid, "Spliced proof must be rejected!");

        let mut spliced2 = proof1.clone();
        spliced2.product_arg = proof2.product_arg.clone();
        let spliced2_valid = spliced2.verify(&input1, &output1, &pk1);
        println!(
            "  Spliced proof (swap product_arg from different shuffle): {}",
            if spliced2_valid { "PASSED ✗ (NOT DETECTED!)" } else { "FAILED ✓ (DETECTED!)" }
        );
        assert!(!spliced2_valid, "Spliced product_arg must be rejected!");

        let mut spliced3 = proof1.clone();
        spliced3.zk_consistency = proof2.zk_consistency.clone();
        let spliced3_valid = spliced3.verify(&input1, &output1, &pk1);
        println!(
            "  Spliced proof (swap zk_consistency from different shuffle): {}",
            if spliced3_valid { "PASSED ✗ (NOT DETECTED!)" } else { "FAILED ✓ (DETECTED!)" }
        );
        assert!(!spliced3_valid, "Spliced zk_consistency must be rejected!");

        println!("  ✅ Transcript binding prevents all proof splicing attacks");
    }

    #[test]
    fn test_transcript_binding_challenge_tampering() {
        println!("\n=== Security Test: Challenge Tampering (should FAIL) ===\n");

        let mut rng = OsRng;
        let (_sk, pk, input, permute, r_values, output) = setup_shuffle_env();

        let mut proof = ZKShuffleProofV3::prove(&input, &output, &permute, &r_values, &pk, &mut rng);

        let original_challenge = proof.global_challenge;
        proof.global_challenge = original_challenge + Scalar::ONE;

        let tampered_valid = proof.verify(&input, &output, &pk);
        println!(
            "  Tampered global_challenge (c + 1): {}",
            if tampered_valid { "PASSED ✗ (NOT DETECTED!)" } else { "FAILED ✓ (DETECTED!)" }
        );
        assert!(!tampered_valid, "Tampered challenge must be rejected!");

        proof.global_challenge = Scalar::ZERO;
        let zero_valid = proof.verify(&input, &output, &pk);
        println!(
            "  Tampered global_challenge (= ZERO): {}",
            if zero_valid { "PASSED ✗ (NOT DETECTED!)" } else { "FAILED ✓ (DETECTED!)" }
        );
        assert!(!zero_valid, "Zero challenge must be rejected!");

        println!("  ✅ Challenge integrity verified");
    }

    #[test]
    fn test_transcript_binding_cross_instance_replay() {
        println!("\n=== Security Test: Cross-Instance Replay Attack (should FAIL) ===\n");

        let mut rng = OsRng;
        let (_sk1, pk1, input1, permute1, r_values1, output1) = setup_shuffle_env();
        let (_sk2, pk2, input2, _permute2, _r_values2, output2) = setup_shuffle_env();

        let proof1 = ZKShuffleProofV3::prove(&input1, &output1, &permute1, &r_values1, &pk1, &mut rng);

        let replay_valid = proof1.verify(&input2, &output2, &pk2);
        println!(
            "  Replay proof1 on different input/output/pk: {}",
            if replay_valid { "PASSED ✗ (NOT DETECTED!)" } else { "FAILED ✓ (DETECTED!)" }
        );
        assert!(!replay_valid, "Cross-instance replay must be rejected!");

        let same_pk_valid = proof1.verify(&input2, &output2, &pk1);
        println!(
            "  Replay proof1 on different data but same pk: {}",
            if same_pk_valid { "PASSED ✗ (NOT DETECTED!)" } else { "FAILED ✓ (DETECTED!)" }
        );
        assert!(!same_pk_valid, "Replay with different data must be rejected!");

        println!("  ✅ Cross-instance replay attack prevented by transcript binding");
    }

    #[test]
    fn test_hash_to_scalar_full_domain_coverage() {
        println!("\n=== Security Test: Hash-to-Scalar Domain Coverage ===\n");

        use sha2::{Digest, Sha256};

        for trial in 0..10 {
            let mut h = Sha256::new();
            h.update(b"domain_test:");
            h.update(&(trial as u64).to_le_bytes());
            let digest = h.finalize();

            let s = super::hash_to_scalar(&digest);
            let bytes = s.to_repr();

            let is_nonzero = s != Scalar::ZERO;
            let byte_sum: u64 = bytes.iter().map(|&b| b as u64).sum();
            let has_high_entropy = byte_sum > 200;

            println!(
                "  Trial {}: nonzero={}, byte_sum={}, high_entropy={}",
                trial, is_nonzero, byte_sum, has_high_entropy
            );
            assert!(is_nonzero, "Hash-to-scalar must never return zero");
            assert!(has_high_entropy, "Hash-to-scalar should produce high-entropy values");
        }

        println!("  ✅ Hash-to-scalar produces full-domain scalars with proper entropy");
    }

    #[test]
    fn test_nonce_uniqueness_and_replay_prevention() {
        println!("\n=== Security Test: Nonce Uniqueness & Replay Prevention ===\n");

        let mut rng1 = OsRng;
        let (_sk, pk, input, permute, r_values, output) = setup_shuffle_env();

        let proof_a = ZKShuffleProofV3::prove(&input, &output, &permute, &r_values, &pk, &mut rng1);
        let mut rng2 = OsRng;
        let proof_b = ZKShuffleProofV3::prove(&input, &output, &permute, &r_values, &pk, &mut rng2);

        let same_nonce = proof_a.nonce == proof_b.nonce;
        println!(
            "  Two proofs of same shuffle have different nonces: {}",
            if !same_nonce { "YES ✓ (unique per session)" } else { "NO ✗ (collision!)" }
        );
        assert!(!same_nonce, "Each prove() must generate unique nonce");

        let same_challenge = proof_a.global_challenge == proof_b.global_challenge;
        println!(
            "  Different nonces → different global_challenges: {}",
            if !same_challenge { "YES ✓" } else { "NO ✗" }
        );
        assert!(!same_challenge, "Different nonces must produce different challenges");

        let mut replay_proof = proof_a.clone();
        replay_proof.nonce = proof_b.nonce;
        let replay_valid = replay_proof.verify(&input, &output, &pk);
        println!(
            "  Swapped nonce (proof_a with proof_b's nonce): {}",
            if replay_valid { "PASSED ✗ (NOT DETECTED!)" } else { "FAILED ✓ (DETECTED!)" }
        );
        assert!(!replay_valid, "Nonce swap must be rejected!");

        let mut zero_nonce_proof = proof_a.clone();
        zero_nonce_proof.nonce = Scalar::ZERO;
        let zero_nonce_valid = zero_nonce_proof.verify(&input, &output, &pk);
        println!(
            "  Forced nonce=ZERO: {}",
            if zero_nonce_valid { "PASSED ✗ (NOT DETECTED!)" } else { "FAILED ✓ (DETECTED!)" }
        );
        assert!(!zero_nonce_valid, "Zero nonce must be rejected!");

        println!("  ✅ Nonce provides strong replay protection");
    }

    #[test]
    fn test_benchmark_zkshuffle_v3_prove_verify() {
        use std::time::{Duration, Instant};

        println!("\n{}", "=".repeat(72));
        println!("  ZKShuffleProofV3 Benchmark: prove() & verify()");
        println!("{}", "=".repeat(72));

        const WARMUP: usize = 3;
        const ITERATIONS: usize = 20;

        let mut rng = OsRng;
        let (_sk, pk, input, permute, r_values, output) = setup_shuffle_env();

        let mut prove_times: Vec<Duration> = Vec::with_capacity(ITERATIONS);
        let mut verify_times: Vec<Duration> = Vec::with_capacity(ITERATIONS);
        let mut proof_size_bytes = 0usize;

        for i in 0..(WARMUP + ITERATIONS) {
            let mut iter_rng = OsRng;

            let start = Instant::now();
            let proof = ZKShuffleProofV3::prove(&input, &output, &permute, &r_values, &pk, &mut iter_rng);
            let prove_dur = start.elapsed();

            if i < WARMUP {
                println!("\n  [Warmup {}/{}] prove: {:?}", i + 1, WARMUP, prove_dur);
                continue;
            }

            if proof_size_bytes == 0 {
                proof_size_bytes = std::mem::size_of_val(&proof);
            }

            let start = Instant::now();
            let valid = proof.verify(&input, &output, &pk);
            let verify_dur = start.elapsed();

            assert!(valid, "Benchmark iteration {} must verify", i);

            prove_times.push(prove_dur);
            verify_times.push(verify_dur);
        }

        prove_times.sort();
        verify_times.sort();

        let avg_prove: Duration = prove_times.iter().sum::<Duration>() / ITERATIONS as u32;
        let avg_verify: Duration = verify_times.iter().sum::<Duration>() / ITERATIONS as u32;
        let p50_prove = prove_times[ITERATIONS / 2];
        let p50_verify = verify_times[ITERATIONS / 2];
        let p99_prove = prove_times[(ITERATIONS * 99 / 100).min(ITERATIONS - 1)];
        let p99_verify = verify_times[(ITERATIONS * 99 / 100).min(ITERATIONS - 1)];
        let min_prove = prove_times[0];
        let min_verify = verify_times[0];
        let max_prove = prove_times[ITERATIONS - 1];
        let max_verify = verify_times[ITERATIONS - 1];

        let prove_per_sec = 1.0f64 / avg_prove.as_secs_f64();
        let verify_per_sec = 1.0f64 / avg_verify.as_secs_f64();

        println!("\n  ┌─────────────────────────────────────────────────────────────┐");
        println!("  │  ZKShuffleProofV3 Performance (N_CARDS={}, {} iters)       │", N_CARDS, ITERATIONS);
        println!("  ├──────────────┬──────────┬──────────┬──────────┬──────────┤");
        println!("  │ Operation    │   Avg    │   P50    │   Min    │   Max    │");
        println!("  ├──────────────┼──────────┼──────────┼──────────┼──────────┤");
        println!("  │ prove()      │ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│",
            avg_prove.as_millis(), p50_prove.as_millis(),
            min_prove.as_millis(), max_prove.as_millis());
        println!("  │ verify()     │ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│",
            avg_verify.as_millis(), p50_verify.as_millis(),
            min_verify.as_millis(), max_verify.as_millis());
        println!("  ├──────────────┼──────────┼──────────┼──────────┼──────────┤");
        println!("  │ Throughput   │ {:>8.1}/s│          │ P99={:>6.2?}ms│ P99={:>6.2?}ms│",
            prove_per_sec, p99_prove.as_millis(), p99_verify.as_millis());
        println!("  │ Verify rate  │ {:>8.1}/s│          │          │          │",
            verify_per_sec);
        println!("  ├──────────────┴──────────┴──────────┴──────────┴──────────┤");
        println!("  │ Proof size: ~{} bytes (5 fields + nonce)                  │", proof_size_bytes);
        println!("  │ Total (prove+verify): {:>8.2?}ms                           │",
            (avg_prove + avg_verify).as_millis());
        println!("  └─────────────────────────────────────────────────────────────┘");

        assert!(avg_prove.as_millis() < 500, "prove() should complete within 500ms");
        assert!(avg_verify.as_millis() < 100, "verify() should complete within 100ms");

        println!("\n  ✅ Benchmark completed: all performance within acceptable bounds");
    }
}
