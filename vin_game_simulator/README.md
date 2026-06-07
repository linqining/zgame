# Vin Poker Game Simulator

A complete poker game flow simulator for debugging vin_server.

## Features

- ✅ **Complete game lifecycle simulation** (join → shuffle → bet → showdown)
- ✅ **Multi-player support** (2-10 players with independent key pairs)
- ✅ **HTTP-based communication** (no WebSocket required)
- ✅ **Automatic game state polling**
- ✅ **Smart AI decision making** (fold/call/raise/check based on chip position)
- ✅ **Detailed logging and status tracking**
- ✅ **Integration with vin_server API**

### 🔐 Cryptographic Features

- ✅ **Real key pair generation** - Each player generates unique ECDSA key pair
- ✅ **PK ownership proof** - Zero-knowledge proof of public key ownership
- ✅ **ElGamal encryption support** - Full Mental Poker protocol compatibility

## Prerequisites

- Rust 1.74+
- Running vin_server at `http://localhost:3000`

## Installation

```bash
cd app/vin_game_simulator
cargo build --release
```

## Usage

### Basic Usage (2 players on table 1)

```bash
./run_simulation.sh
# or
./target/release/vin_game_simulator
```

### Custom Table and Player Count

```bash
# Simulate with 4 players on table 2
./target/release/vin_game_simulator 2 4

# Simulate with 6 players on table 3
./target/release/vin_game_simulator 3 6
```

### Using the Shell Script

```bash
# Table 1, 2 players (default)
./run_simulation.sh

# Table 2, 4 players
./run_simulation.sh 2 4
```

## Game Flow

The simulator automatically performs the following steps:

1. **👥 Join Table** - Add simulated players to the specified table
2. **🔀 Shuffle** - Submit shuffle data for each player
3. **⏳ Wait for Game Start** - Poll game state until game begins
4. **🎰 Auto-Play** - Automatically make decisions:
   - Check when no bet to call
   - Call when affordable (< 50% of chips)
   - Raise occasionally (30% chance)
   - Fold when expensive (> 100% of chips)
5. **🏆 Showdown** - Display final results and winner

## Output Example

```
============================================================
🎮 VIN POKER GAME SIMULATOR
Simulating a complete game with 2 players on table 1
============================================================

👤 Adding player: Player1...
   🔑 Generated key pair for Player1
      Public Key: 02abcdef123456...
   ✅ Player1 joined and shuffled successfully

👤 Adding player: Player2...
   🔑 Generated key pair for Player2
      Public Key: 02fedcba098765...
   ✅ Player2 joined and shuffled successfully

📋 Player Key Information:
   👤 Player: Player1
      🔑 Public Key: 02abcdef1234567890...
      🔒 Secret Key: a1b2c3d4e5f6a7b8c9d0...
   👤 Player: Player2
      🔑 Public Key: 02fedcba0987654321...
      🔒 Secret Key: f1e2d3c4b5a69876f5e4...

⏳ Waiting for game to start...

🎰 Starting automated gameplay...

--- Round 1 --- Phase: PreFlop, Pot: 30
   🎲 Player1 (chips: 990) turn
      Available actions: ["fold", "call", "raise"]
      🤖 Auto-play: call (None)
      ✅ Action succeeded

--- Round 2 --- Phase: PreFlop, Pot: 60
   🎲 Player2 (chips: 980) turn
      Available actions: ["fold", "check", "raise"]
      🤖 Auto-play: check (None)
      ✅ Action succeeded

... (game continues through Flop, Turn, River)

🏆 Hand complete!

============================================================
FINAL GAME STATE
============================================================
Phase: HandComplete
Pot: 240

Winners:
   Player1 wins $240.00

Players:
  Seat 1: Player1 - Chips: 1220, Folded: false
  Seat 2: Player2 - Chips: 780, Folded: true
============================================================

✅ Simulation completed!
```

## Architecture

### Components

```
GameSimulator
├── HTTP Client (reqwest)
│   ├── POST /games/{id}/join-and-shuffle (join + shuffle)
│   ├── POST /games/{id}/action (fold/call/raise/check)
│   ├── POST /games/{id}/reveal-token (submit reveal tokens)
│   └── GET /tables/{id} (poll game state)
├── SimulatedPlayer(s) with ClientPlayer
│   ├── Name & identity
│   ├── 🔑 Real ECDSA key pair (sk, pk)
│   ├── 🔐 Cryptographic operations
│   └── Local state cache
└── Decision Engine
    ├── Analyze game state
    ├── Evaluate chip position
    └── Choose optimal action
```

### Key Data Structures

- **SimulatedPlayer**: Player with cryptographic capabilities
  - Contains `ClientPlayer` from z_game library
  - Manages key pair and crypto operations
- **ClientPlayer** (from z_game): Core cryptographic engine
  - `sk: Scalar` - Secret key
  - `pk: EcPoint` - Public key
  - Methods for encryption, decryption, proofs
- **GameSimulator**: Orchestrates entire simulation

## API Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/games/{id}/join-and-shuffle` | POST | Join table and submit shuffle |
| `/games/{id}/action` | POST | Submit player action (fold/call/raise/check) |
| `/games/{id}/reveal-token` | POST | Submit reveal tokens |
| `/tables/{id}` | GET | Poll current game state |

## Decision Logic

The AI uses simple but effective heuristics:

1. **No bet to call** → 70% check, 30% raise (2x big blind)
2. **Affordable call** (≤50% stack) → 70% call, 30% fold
3. **Moderate call** (≤100% stack) → 40% call, 60% fold
4. **Expensive call** (>100% stack) → Always fold
5. **Non-betting phases** → Always check

## Testing

To test the simulator:

1. Start the vin_server:
   ```bash
   cd app/vin_server
   cargo run
   ```

2. In another terminal, run the simulator:
   ```bash
   cd app/vin_game_simulator
   cargo run --release
   # or with custom parameters
   cargo run --release -- 2 4
   ```

3. Watch the complete game unfold in real-time!

## Troubleshooting

### Connection Refused
- Ensure vin_server is running on port 3000
- Check firewall settings

### Game Not Starting
- Make sure at least 2 players join the table
- Check that table exists (tables 1, 2, 3 are pre-created)

### Slow Gameplay
- Increase polling interval in `auto_play_round()` if needed
- Server may be processing cryptographic operations

## Differences from game_simulator

This simulator is specifically designed for vin_server:

- Uses HTTP polling instead of WebSocket for real-time updates
- Uses Socket.IO event names compatible with vin_server
- Simplified shuffle/reveal protocol (no full crypto implementation)
- Designed for debugging vin_server game loop and state management

## Integration Notes

This simulator works seamlessly with:
- ✅ vin_server HTTP API
- ✅ vin_server game loop
- ✅ vin_server table management
- ✅ vin_server betting round logic

## License

MIT License - Part of secret-poker project