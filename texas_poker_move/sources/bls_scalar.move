module texas_poker::bls_scalar;

use sui::bls12381;
use sui::bls12381::Scalar;
use sui::group_ops;
use std::hash;

// ========== 常量 ==========
const N_CARDS: u64 = 52;

#[error]
const EMSMLengthMismatch: vector<u8> = b"scalars and points length mismatch in g1_msm";

// ========== 标量辅助函数 ==========

/// 将任意数据哈希为 BLS12-381 标量
/// SHA3-256(data) → 32 bytes，清除最高2位确保 < 曲线阶
///
/// M-P18: 字节序说明——SHA3-256 输出为大端序字节流。
/// h[0] 是最高有效字节（MSB），清除 h[0] 的高 2 位（& 0x3F）即可将值限制在 2^254 以下。
/// 注意：BLS12-381 曲线阶 r ≈ 2^255，清除高 2 位后值 < 2^254 < r，确保标量合法。
/// 此处不是小端序——若误用小端序应清除 h[31] 而非 h[0]，但 SHA3 输出为大端，故清除 h[0] 正确。
public fun hash_to_scalar(data: &vector<u8>): group_ops::Element<Scalar> {
    let mut h = hash::sha3_256(*data);
    // 清除最高2位（大端序下 h[0] 的最高 2 位），确保值 < 2^254 < BLS12-381 曲线阶
    let first = *(vector::borrow(&h, 0));
    *(vector::borrow_mut(&mut h, 0)) = first & 0x3F;
    bls12381::scalar_from_bytes(&h)
}

/// 从密文和私钥派生标量
/// SHA3-256(len(c1_sk) || c1_sk || len(c2_sk) || c2_sk) → hash_to_scalar
/// m6 修复：添加长度前缀防止歧义编码
public fun derive_scalar_from_card_and_sk(
    c1_sk: &vector<u8>,
    c2_sk: &vector<u8>,
): group_ops::Element<Scalar> {
    let mut data = vector[];
    // 长度前缀（4 字节小端）
    let len1 = c1_sk.length();
    data.push_back(((len1) & 0xFF) as u8);
    data.push_back(((len1 >> 8) & 0xFF) as u8);
    data.push_back(((len1 >> 16) & 0xFF) as u8);
    data.push_back(((len1 >> 24) & 0xFF) as u8);
    let mut i = 0;
    while (i < c1_sk.length()) {
        data.push_back(*(vector::borrow(c1_sk, i)));
        i = i + 1;
    };
    let len2 = c2_sk.length();
    data.push_back(((len2) & 0xFF) as u8);
    data.push_back(((len2 >> 8) & 0xFF) as u8);
    data.push_back(((len2 >> 16) & 0xFF) as u8);
    data.push_back(((len2 >> 24) & 0xFF) as u8);
    i = 0;
    while (i < c2_sk.length()) {
        data.push_back(*(vector::borrow(c2_sk, i)));
        i = i + 1;
    };
    hash_to_scalar(&data)
}

/// 从密文和公钥派生标量
/// SHA3-256(len(c1) || c1 || len(c2) || c2 || len(pk) || pk) → hash_to_scalar
/// m6 修复：添加长度前缀防止歧义编码
public fun derive_scalar_from_card_and_pk(
    c1: &vector<u8>,
    c2: &vector<u8>,
    pk: &vector<u8>,
): group_ops::Element<Scalar> {
    let mut data = vector[];
    // 长度前缀（4 字节小端）
    let len1 = c1.length();
    data.push_back(((len1) & 0xFF) as u8);
    data.push_back(((len1 >> 8) & 0xFF) as u8);
    data.push_back(((len1 >> 16) & 0xFF) as u8);
    data.push_back(((len1 >> 24) & 0xFF) as u8);
    let mut i = 0;
    while (i < c1.length()) {
        data.push_back(*(vector::borrow(c1, i)));
        i = i + 1;
    };
    let len2 = c2.length();
    data.push_back(((len2) & 0xFF) as u8);
    data.push_back(((len2 >> 8) & 0xFF) as u8);
    data.push_back(((len2 >> 16) & 0xFF) as u8);
    data.push_back(((len2 >> 24) & 0xFF) as u8);
    i = 0;
    while (i < c2.length()) {
        data.push_back(*(vector::borrow(c2, i)));
        i = i + 1;
    };
    let len3 = pk.length();
    data.push_back(((len3) & 0xFF) as u8);
    data.push_back(((len3 >> 8) & 0xFF) as u8);
    data.push_back(((len3 >> 16) & 0xFF) as u8);
    data.push_back(((len3 >> 24) & 0xFF) as u8);
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

/// 多标量乘法（MSM）：sum(scalars[i] * points[i])
///
/// 注意：Sui testnet 的 `bls12381::g1_multi_scalar_multiplication` 原生实现
/// 在当前协议版本下不可用（abort ENotSupported），因此使用 `g1_mul` + `g1_add`
/// 循环实现等价功能。功能完全等价，仅性能差异。
public fun g1_msm(
    scalars: &vector<group_ops::Element<Scalar>>,
    points: &vector<group_ops::Element<bls12381::G1>>,
): group_ops::Element<bls12381::G1> {
    let n = scalars.length();
    assert!(n == points.length(), EMSMLengthMismatch);
    if (n == 0) {
        return bls12381::g1_identity()
    };
    // 使用 g1_mul 循环替代 g1_multi_scalar_multiplication
    let mut result = bls12381::g1_identity();
    let mut i = 0;
    while (i < n) {
        let term = bls12381::g1_mul(vector::borrow(scalars, i), vector::borrow(points, i));
        result = bls12381::g1_add(&result, &term);
        i = i + 1;
    };
    result
}

/// G1 点相等比较
public fun g1_equal(a: &group_ops::Element<bls12381::G1>, b: &group_ops::Element<bls12381::G1>): bool {
    group_ops::equal(a, b)
}

/// DLEq 验证：检查 s * g == commitment + c * pk
/// 用于 Schnorr/Chaum-Pedersen 风格证明的统一验证等式。
/// g: 基点, pk: 公钥点, commitment: 承诺点, s: 响应标量, c: 挑战标量
public fun verify_dleq(
    g: &group_ops::Element<bls12381::G1>,
    pk: &group_ops::Element<bls12381::G1>,
    commitment: &group_ops::Element<bls12381::G1>,
    s: &group_ops::Element<Scalar>,
    c: &group_ops::Element<Scalar>,
): bool {
    let lhs = bls12381::g1_mul(s, g);
    let pk_c = bls12381::g1_mul(c, pk);
    let rhs = bls12381::g1_add(commitment, &pk_c);
    g1_equal(&lhs, &rhs)
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
