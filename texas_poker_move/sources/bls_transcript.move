module texas_poker::bls_transcript;

use sui::bls12381;
use sui::bls12381::Scalar;
use sui::group_ops;
use std::hash;
use texas_poker::bls_scalar;
use texas_poker::bls_elgamal::{Self, ElGamalCiphertext};

// ========== Transcript 结构体 ==========

/// Fiat-Shamir Transcript，替代 Rust 中的 Merlin Transcript
/// 使用 SHA3-256 增量哈希
public struct Transcript has store, drop {
    state: vector<u8>,
}

// ========== 构造函数 ==========

/// 创建新 Transcript，带协议名称
public fun new(protocol_name: &vector<u8>): Transcript {
    let state = hash::sha3_256(*protocol_name);
    Transcript { state }
}

// ========== 追加数据 ==========

/// 追加 G1 点
public fun append_point(t: &mut Transcript, label: &vector<u8>, point: &group_ops::Element<bls12381::G1>) {
    let point_bytes = *group_ops::bytes(point);
    append_message(t, label, &point_bytes);
}

/// 批量追加 G1 点向量，所有点使用同一 label
public fun append_points(t: &mut Transcript, label: &vector<u8>, points: &vector<group_ops::Element<bls12381::G1>>) {
    let mut i = 0;
    while (i < points.length()) {
        append_point(t, label, vector::borrow(points, i));
        i = i + 1;
    };
}

/// 批量追加密文向量，每个密文的 c1 用 c1_label、c2 用 c2_label
public fun append_ciphertexts(
    t: &mut Transcript,
    c1_label: &vector<u8>,
    c2_label: &vector<u8>,
    cts: &vector<ElGamalCiphertext>,
) {
    let mut i = 0;
    while (i < cts.length()) {
        let ct = vector::borrow(cts, i);
        append_point(t, c1_label, bls_elgamal::c1(ct));
        append_point(t, c2_label, bls_elgamal::c2(ct));
        i = i + 1;
    };
}

/// 追加标量
public fun append_scalar(t: &mut Transcript, label: &vector<u8>, scalar: &group_ops::Element<Scalar>) {
    let scalar_bytes = *group_ops::bytes(scalar);
    append_message(t, label, &scalar_bytes);
}

/// 追加任意消息
///
/// M-P13: 为防止长度扩展攻击和歧义编码，在 label 和 message 前分别添加
/// 4 字节小端长度前缀。这样不同 (label, message) 对的拼接结果唯一。
public fun append_message(t: &mut Transcript, label: &vector<u8>, message: &vector<u8>) {
    let mut data = *(&t.state);
    // 追加 label 长度前缀（4 字节小端）
    let label_len = label.length();
    data.push_back(((label_len) & 0xFF) as u8);
    data.push_back(((label_len >> 8) & 0xFF) as u8);
    data.push_back(((label_len >> 16) & 0xFF) as u8);
    data.push_back(((label_len >> 24) & 0xFF) as u8);
    // 追加 label
    let mut i = 0;
    while (i < label.length()) {
        data.push_back(*(vector::borrow(label, i)));
        i = i + 1;
    };
    // 追加 message 长度前缀（4 字节小端）
    let msg_len = message.length();
    data.push_back(((msg_len) & 0xFF) as u8);
    data.push_back(((msg_len >> 8) & 0xFF) as u8);
    data.push_back(((msg_len >> 16) & 0xFF) as u8);
    data.push_back(((msg_len >> 24) & 0xFF) as u8);
    // 追加 message
    i = 0;
    while (i < message.length()) {
        data.push_back(*(vector::borrow(message, i)));
        i = i + 1;
    };
    t.state = hash::sha3_256(data);
}

// ========== 挑战生成 ==========

/// 生成挑战标量
public fun challenge(t: &mut Transcript, label: &vector<u8>): group_ops::Element<Scalar> {
    let challenge_label = b"challenge";
    append_message(t, label, &challenge_label);
    bls_scalar::hash_to_scalar(&t.state)
}

/// 批量生成挑战标量
public fun challenge_vec(t: &mut Transcript, label: &vector<u8>, n: u64): vector<group_ops::Element<Scalar>> {
    let mut challenges = vector[];
    let mut i = 0;
    while (i < n) {
        // 每次用带索引的子标签
        let mut sub_label = *label;
        let idx_bytes = bls_scalar::u64_to_ascii(i);
        let mut j = 0;
        while (j < idx_bytes.length()) {
            sub_label.push_back(*(vector::borrow(&idx_bytes, j)));
            j = j + 1;
        };
        challenges.push_back(challenge(t, &sub_label));
        i = i + 1;
    };
    challenges
}

// ========== 访问器 ==========

/// 获取当前状态（仅用于测试调试）
#[test_only]
public fun state(t: &Transcript): &vector<u8> {
    &t.state
}
