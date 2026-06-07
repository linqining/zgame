module texas_poker::bls_scalar;

use sui::bls12381;
use sui::bls12381::Scalar;
use sui::group_ops;
use std::hash;

// ========== 常量 ==========
const N_CARDS: u64 = 52;
const MSM_MAX: u64 = 32;

// ========== 标量辅助函数 ==========

/// 将任意数据哈希为 BLS12-381 标量
/// SHA3-256(data) → 32 bytes，清除最高2位确保 < 曲线阶
public fun hash_to_scalar(data: &vector<u8>): group_ops::Element<Scalar> {
    let mut h = hash::sha3_256(*data);
    // 清除最高2位，确保值 < 2^254 < BLS12-381 曲线阶
    let first = *(vector::borrow(&h, 0));
    *(vector::borrow_mut(&mut h, 0)) = first & 0x3F;
    bls12381::scalar_from_bytes(&h)
}

/// 从密文和私钥派生标量
/// SHA3-256(c1*sk_bytes || c2*sk_bytes) → hash_to_scalar
public fun derive_scalar_from_card_and_sk(
    c1_sk: &vector<u8>,
    c2_sk: &vector<u8>,
): group_ops::Element<Scalar> {
    let mut data = *c1_sk;
    let mut i = 0;
    while (i < c2_sk.length()) {
        data.push_back(*(vector::borrow(c2_sk, i)));
        i = i + 1;
    };
    hash_to_scalar(&data)
}

/// 从密文和公钥派生标量
/// SHA3-256(c1_bytes || c2_bytes || pk_bytes) → hash_to_scalar
public fun derive_scalar_from_card_and_pk(
    c1: &vector<u8>,
    c2: &vector<u8>,
    pk: &vector<u8>,
): group_ops::Element<Scalar> {
    let mut data = *c1;
    let mut i = 0;
    while (i < c2.length()) {
        data.push_back(*(vector::borrow(c2, i)));
        i = i + 1;
    };
    i = 0;
    while (i < pk.length()) {
        data.push_back(*(vector::borrow(pk, i)));
        i = i + 1;
    };
    hash_to_scalar(&data)
}

/// 生成52个确定性明文牌点
/// 对 i=0..51: hash_to_g1("texas_poker/card/{i}")
public fun generate_plaintext_cards(): vector<group_ops::Element<bls12381::G1>> {
    let mut cards = vector[];
    let mut i = 0;
    while (i < N_CARDS) {
        let mut label_bytes = b"texas_poker/card/";
        // 追加数字后缀
        let num_str = u64_to_ascii(i);
        let mut j = 0;
        while (j < num_str.length()) {
            label_bytes.push_back(*(vector::borrow(&num_str, j)));
            j = j + 1;
        };
        cards.push_back(bls12381::hash_to_g1(&label_bytes));
        i = i + 1;
    };
    cards
}

/// 派生独立基点 H
/// hash_to_g1("texas_poker_independent_base_H")
public fun base_h(): group_ops::Element<bls12381::G1> {
    let label = b"texas_poker_independent_base_H";
    bls12381::hash_to_g1(&label)
}

// ========== 标量运算包装 ==========

public fun scalar_zero(): group_ops::Element<Scalar> { bls12381::scalar_zero() }

public fun scalar_one(): group_ops::Element<Scalar> { bls12381::scalar_one() }

public fun scalar_from_u64(x: u64): group_ops::Element<Scalar> { bls12381::scalar_from_u64(x) }

public fun scalar_add(a: &group_ops::Element<Scalar>, b: &group_ops::Element<Scalar>): group_ops::Element<Scalar> {
    bls12381::scalar_add(a, b)
}

public fun scalar_sub(a: &group_ops::Element<Scalar>, b: &group_ops::Element<Scalar>): group_ops::Element<Scalar> {
    bls12381::scalar_sub(a, b)
}

public fun scalar_mul(a: &group_ops::Element<Scalar>, b: &group_ops::Element<Scalar>): group_ops::Element<Scalar> {
    bls12381::scalar_mul(a, b)
}

public fun scalar_neg(a: &group_ops::Element<Scalar>): group_ops::Element<Scalar> {
    bls12381::scalar_neg(a)
}

public fun scalar_inv(a: &group_ops::Element<Scalar>): group_ops::Element<Scalar> {
    bls12381::scalar_inv(a)
}

public fun scalar_from_bytes(bytes: &vector<u8>): group_ops::Element<Scalar> {
    bls12381::scalar_from_bytes(bytes)
}

// ========== G1 辅助函数 ==========

/// 分块 MSM：g1_multi_scalar_multiplication 最多32对
/// 将超过32对的拆分为多个块，结果相加
public fun g1_msm(
    scalars: &vector<group_ops::Element<Scalar>>,
    points: &vector<group_ops::Element<bls12381::G1>>,
): group_ops::Element<bls12381::G1> {
    let n = scalars.length();
    assert!(n == points.length(), 0);
    if (n == 0) {
        return bls12381::g1_identity()
    };
    if (n <= MSM_MAX) {
        return bls12381::g1_multi_scalar_multiplication(scalars, points)
    };
    // 分块处理
    let mut result = bls12381::g1_identity();
    let mut i = 0;
    while (i < n) {
        let end = if (i + MSM_MAX < n) { i + MSM_MAX } else { n };
        let mut chunk_scalars = vector[];
        let mut chunk_points = vector[];
        let mut j = i;
        while (j < end) {
            chunk_scalars.push_back(*(vector::borrow(scalars, j)));
            chunk_points.push_back(*(vector::borrow(points, j)));
            j = j + 1;
        };
        let chunk_result = bls12381::g1_multi_scalar_multiplication(&chunk_scalars, &chunk_points);
        result = bls12381::g1_add(&result, &chunk_result);
        i = end;
    };
    result
}

/// G1 点相等比较
public fun g1_equal(a: &group_ops::Element<bls12381::G1>, b: &group_ops::Element<bls12381::G1>): bool {
    group_ops::equal(a, b)
}

/// 判断 G1 点是否为单位元
public fun g1_is_identity(p: &group_ops::Element<bls12381::G1>): bool {
    group_ops::equal(p, &bls12381::g1_identity())
}

/// G1 点序列化为字节
public fun g1_to_bytes(p: &group_ops::Element<bls12381::G1>): vector<u8> {
    *group_ops::bytes(p)
}

/// 标量序列化为字节
public fun scalar_to_bytes(s: &group_ops::Element<Scalar>): vector<u8> {
    *group_ops::bytes(s)
}

// ========== 辅助函数 ==========

/// u64 转 ASCII 字节表示
public fun u64_to_ascii(n: u64): vector<u8> {
    if (n == 0) {
        return vector[48] // '0'
    };
    let mut digits = vector[];
    let mut val = n;
    while (val > 0) {
        let digit = (val % 10) as u8;
        digits.push_back(digit + 48); // ASCII '0' = 48
        val = val / 10;
    };
    // 反转
    let mut result = vector[];
    let mut i = digits.length();
    while (i > 0) {
        i = i - 1;
        result.push_back(*(vector::borrow(&digits, i)));
    };
    result
}
