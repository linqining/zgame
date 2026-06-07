module texas_poker::bls_transcript;

use sui::bls12381;
use sui::bls12381::Scalar;
use sui::group_ops;
use std::hash;
use texas_poker::bls_scalar;

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

/// 追加标量
public fun append_scalar(t: &mut Transcript, label: &vector<u8>, scalar: &group_ops::Element<Scalar>) {
    let scalar_bytes = *group_ops::bytes(scalar);
    append_message(t, label, &scalar_bytes);
}

/// 追加任意消息
public fun append_message(t: &mut Transcript, label: &vector<u8>, message: &vector<u8>) {
    let mut data = *(&t.state);
    // 追加 label
    let mut i = 0;
    while (i < label.length()) {
        data.push_back(*(vector::borrow(label, i)));
        i = i + 1;
    };
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

/// 获取当前状态（用于调试）
public fun state(t: &Transcript): &vector<u8> {
    &t.state
}
