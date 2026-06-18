module texas_poker::side_pot;

// M-P10: 溢出保护——单局总下注上限 10^18（远超任何实际筹码量）。
// u64 最大值约 1.8*10^19，此处限制为 10^18 留足安全余量。
const MAX_TOTAL_BET: u64 = 1000000000000000000;

// ========== 边池 ==========
public struct SidePot has store, copy, drop {
    amount: u64,
    eligible_seats: vector<u64>,
}

// ========== 构造/访问 ==========
public fun new_side_pot(amount: u64, eligible_seats: vector<u64>): SidePot {
    SidePot { amount, eligible_seats }
}

public fun amount(sp: &SidePot): u64 { sp.amount }
public fun eligible_seats(sp: &SidePot): &vector<u64> { &sp.eligible_seats }

// ========== 计算边池 ==========
public fun calculate_side_pots(
    bets: &vector<u64>,
    folded: &vector<bool>,
    all_in: &vector<bool>,
): (u64, vector<SidePot>) {
    let n = bets.length();
    let total_pot = sum_bets(bets);
    let mut all_in_bets = collect_all_in_bets(bets, all_in);

    if (all_in_bets.length() == 0) {
        return (total_pot, vector[])
    };

    sort_ascending(&mut all_in_bets);

    let mut side_pots = vector[];
    let mut prev_level = 0;

    let mut i = 0;
    while (i < all_in_bets.length()) {
        let level = all_in_bets[i];
        if (level <= prev_level) {
            i = i + 1;
            continue
        };

        let mut pot_amount = 0;
        let mut eligible = vector[];
        let mut j = 0;
        while (j < n) {
            let bet = bets[j];
            if (bet > prev_level) {
                let contribution = if (bet < level) { bet - prev_level } else { level - prev_level };
                pot_amount = pot_amount + contribution;
                if (!folded[j]) {
                    eligible.push_back(j);
                };
            };
            j = j + 1;
        };

        if (pot_amount > 0) {
            side_pots.push_back(new_side_pot(pot_amount, eligible));
        };

        prev_level = level;
        i = i + 1;
    };

    // 最外层（超出最大 all-in 的部分）
    let mut outer_amount = 0;
    let mut outer_eligible = vector[];
    let mut k = 0;
    while (k < n) {
        let bet = bets[k];
        if (bet > prev_level) {
            outer_amount = outer_amount + (bet - prev_level);
            if (!folded[k]) {
                outer_eligible.push_back(k);
            };
        };
        k = k + 1;
    };

    if (outer_amount > 0) {
        side_pots.push_back(new_side_pot(outer_amount, outer_eligible));
    };

    // M-A3 修复：当最后一个 side_pot（outer pot）的 eligible 为空时
    // （所有超额贡献者都 folded），将其金额合并到上一个有 eligible 的 pot 层级，
    // 避免筹码丢失。如果没有上一个有 eligible 的层级，合并到第一个 pot（main pot）。
    if (side_pots.length() > 0) {
        let last_idx = side_pots.length() - 1;
        let last_pot = vector::borrow(&side_pots, last_idx);
        if (last_pot.eligible_seats.length() == 0 && last_pot.amount > 0) {
            let merge_amount = last_pot.amount;
            side_pots.pop_back();
            if (side_pots.length() > 0) {
                let mut merge_idx = 0;
                let mut k = side_pots.length();
                while (k > 0) {
                    k = k - 1;
                    if (vector::borrow(&side_pots, k).eligible_seats.length() > 0) {
                        merge_idx = k;
                        break
                    };
                };
                let pot_ref = vector::borrow_mut(&mut side_pots, merge_idx);
                pot_ref.amount = pot_ref.amount + merge_amount;
            };
        };
    };

    // 主池 = 第一个边池
    if (side_pots.length() > 0) {
        let first = side_pots[0];
        let mut rest = vector[];
        let mut idx = 1;
        while (idx < side_pots.length()) {
            rest.push_back(side_pots[idx]);
            idx = idx + 1;
        };
        (first.amount, rest)
    } else {
        (total_pot, vector[])
    }
}

fun sum_bets(bets: &vector<u64>): u64 {
    // M-P10: 溢出保护——使用 MAX_TOTAL_BET 上限校验，防止静默溢出
    let mut total = 0;
    let mut i = 0;
    while (i < bets.length()) {
        total = total + bets[i];
        assert!(total <= MAX_TOTAL_BET, 0);
        i = i + 1;
    };
    total
}

fun collect_all_in_bets(bets: &vector<u64>, all_in: &vector<bool>): vector<u64> {
    let mut result = vector[];
    let mut i = 0;
    while (i < bets.length()) {
        if (all_in[i] && bets[i] > 0) {
            let bet = bets[i];
            let mut found = false;
            let mut j = 0;
            while (j < result.length()) {
                if (result[j] == bet) { found = true };
                j = j + 1;
            };
            if (!found) {
                result.push_back(bet);
            };
        };
        i = i + 1;
    };
    result
}

fun sort_ascending(v: &mut vector<u64>) {
    let n = v.length();
    let mut i = 0;
    while (i < n) {
        let mut j = i + 1;
        while (j < n) {
            // M-P9: 当前 Move 版本不支持 v[i] = vj 作为左值，保留 vector::borrow_mut 语法
            if (v[i] > v[j]) {
                let tmp = v[i];
                let vj = v[j];
                *(vector::borrow_mut(v, i)) = vj;
                *(vector::borrow_mut(v, j)) = tmp;
            };
            j = j + 1;
        };
        i = i + 1;
    };
}
