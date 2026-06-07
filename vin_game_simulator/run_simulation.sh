#!/bin/bash

echo "🎮 Vin Poker Game Simulator"
echo "============================"

TABLE_ID=${1:-1}
NUM_PLAYERS=${2:-2}

echo "Table ID: $TABLE_ID"
echo "Number of Players: $NUM_PLAYERS"
echo ""

cd "$(dirname "$0")"

if [ ! -f "Cargo.toml" ]; then
    echo "❌ Error: Cargo.toml not found"
    exit 1
fi

echo "📦 Building simulator..."
cargo build --release

if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi

echo "✅ Build successful"
echo ""
echo "🚀 Running simulation..."
echo ""

./target/release/vin_game_simulator $TABLE_ID $NUM_PLAYERS
