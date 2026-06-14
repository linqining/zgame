module texas_poker::bls_elgamal;

use sui::bls12381;
use sui::bls12381::{Scalar, G1};
use sui::group_ops;
use texas_poker::bls_scalar;

// ========== ElGamal 密文 ==========

/// 基于 BLS12-381 G1 的 ElGamal 密文
/// c1 = G * r（临时公钥）
/// c2 = M + pk * r（加密消息）
public struct ElGamalCiphertext has store, copy, drop {
    c1: group_ops::Element<G1>,
    c2: group_ops::Element<G1>,
}

#[error]
const EC1IsIdentity: vector<u8> = b"c1 is identity point, cannot remask";

// ========== 加密操作 ==========

/// ElGamal 加密：c1 = G*r, c2 = M + pk*r
public fun encrypt(
    plaintext: &group_ops::Element<G1>,
    pk: &group_ops::Element<G1>,
    r: &group_ops::Element<Scalar>,
): ElGamalCiphertext {
    let c1 = bls12381::g1_mul(r, &bls12381::g1_generator());
    let pk_r = bls12381::g1_mul(r, pk);
    let c2 = bls12381::g1_add(plaintext, &pk_r);
    ElGamalCiphertext { c1, c2 }
}

/// 重加密：c1 += G*r', c2 += pk*r'
public fun re_encrypt(
    ct: &ElGamalCiphertext,
    pk: &group_ops::Element<G1>,
    r: &group_ops::Element<Scalar>,
): ElGamalCiphertext {
    let g_r = bls12381::g1_mul(r, &bls12381::g1_generator());
    let pk_r = bls12381::g1_mul(r, pk);
    ElGamalCiphertext {
        c1: bls12381::g1_add(&ct.c1, &g_r),
        c2: bls12381::g1_add(&ct.c2, &pk_r),
    }
}

/// 解密：M = c2 - c1*sk
public fun decrypt(ct: &ElGamalCiphertext, sk: &group_ops::Element<Scalar>): group_ops::Element<G1> {
    let c1_sk = bls12381::g1_mul(sk, &ct.c1);
    bls12381::g1_sub(&ct.c2, &c1_sk)
}

/// 生成揭牌令牌：token = c1 * sk
public fun gen_reveal_token(ct: &ElGamalCiphertext, sk: &group_ops::Element<Scalar>): group_ops::Element<G1> {
    bls12381::g1_mul(sk, &ct.c1)
}

/// Remask：c2 += c1 * sk（新玩家加入时使用）
public fun remask(ct: &ElGamalCiphertext, sk: &group_ops::Element<Scalar>): ElGamalCiphertext {
    assert!(!bls_scalar::g1_is_identity(&ct.c1), EC1IsIdentity);
    let c1_sk = bls12381::g1_mul(sk, &ct.c1);
    ElGamalCiphertext {
        c1: ct.c1,
        c2: bls12381::g1_add(&ct.c2, &c1_sk),
    }
}

// ========== 验证 ==========

/// 验证密文有效（c1/c2 非 identity）
public fun is_valid(ct: &ElGamalCiphertext): bool {
    !bls_scalar::g1_is_identity(&ct.c1) && !bls_scalar::g1_is_identity(&ct.c2)
}

/// 创建占位牌（c1=c2=identity）
public fun new_placeholder_card(): ElGamalCiphertext {
    ElGamalCiphertext {
        c1: bls12381::g1_identity(),
        c2: bls12381::g1_identity(),
    }
}

// ========== 构造函数 ==========

/// 从 c1、c2 构造 ElGamalCiphertext
public fun new_ciphertext(c1: group_ops::Element<G1>, c2: group_ops::Element<G1>): ElGamalCiphertext {
    ElGamalCiphertext { c1, c2 }
}

// ========== 访问器 ==========

public fun c1(ct: &ElGamalCiphertext): &group_ops::Element<G1> { &ct.c1 }

public fun c2(ct: &ElGamalCiphertext): &group_ops::Element<G1> { &ct.c2 }

public fun c1_bytes(ct: &ElGamalCiphertext): vector<u8> { bls_scalar::g1_to_bytes(&ct.c1) }

public fun c2_bytes(ct: &ElGamalCiphertext): vector<u8> { bls_scalar::g1_to_bytes(&ct.c2) }

/// 序列化密文为 96 字节 (c1 48 bytes + c2 48 bytes)
public fun ciphertext_to_bytes(ct: &ElGamalCiphertext): vector<u8> {
    let mut bytes = c1_bytes(ct);
    let c2_b = c2_bytes(ct);
    let mut i = 0;
    while (i < c2_b.length()) {
        bytes.push_back(c2_b[i]);
        i = i + 1;
    };
    bytes
}

/// 从 96 字节反序列化密文
public fun ciphertext_from_bytes(bytes: &vector<u8>): ElGamalCiphertext {
    assert!(bytes.length() == 96, 0);
    let mut c1_bytes = vector[];
    let mut c2_bytes = vector[];
    let mut i = 0;
    while (i < 48) {
        c1_bytes.push_back(bytes[i]);
        i = i + 1;
    };
    while (i < 96) {
        c2_bytes.push_back(bytes[i]);
        i = i + 1;
    };
    ElGamalCiphertext {
        c1: bls12381::g1_from_bytes(&c1_bytes),
        c2: bls12381::g1_from_bytes(&c2_bytes),
    }
}

// ========== 批量操作 ==========

/// 批量加密52张明文牌
public fun encrypt_batch(
    plaintexts: &vector<group_ops::Element<G1>>,
    pk: &group_ops::Element<G1>,
    randoms: &vector<group_ops::Element<Scalar>>,
): vector<ElGamalCiphertext> {
    let mut result = vector[];
    let mut i = 0;
    while (i < plaintexts.length()) {
        result.push_back(encrypt(
            vector::borrow(plaintexts, i),
            pk,
            vector::borrow(randoms, i),
        ));
        i = i + 1;
    };
    result
}

/// 批量 remask
public fun remask_batch(
    ciphertexts: &vector<ElGamalCiphertext>,
    sk: &group_ops::Element<Scalar>,
): vector<ElGamalCiphertext> {
    let mut result = vector[];
    let mut i = 0;
    while (i < ciphertexts.length()) {
        result.push_back(remask(vector::borrow(ciphertexts, i), sk));
        i = i + 1;
    };
    result
}

/// 提取所有 c1 点
public fun extract_c1s(ciphertexts: &vector<ElGamalCiphertext>): vector<group_ops::Element<G1>> {
    let mut result = vector[];
    let mut i = 0;
    while (i < ciphertexts.length()) {
        result.push_back(ciphertexts[i].c1);
        i = i + 1;
    };
    result
}

/// 提取所有 c2 点
public fun extract_c2s(ciphertexts: &vector<ElGamalCiphertext>): vector<group_ops::Element<G1>> {
    let mut result = vector[];
    let mut i = 0;
    while (i < ciphertexts.length()) {
        result.push_back(ciphertexts[i].c2);
        i = i + 1;
    };
    result
}
