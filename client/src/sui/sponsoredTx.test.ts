import { describe, it, expect } from 'vitest';
import { Transaction, TransactionDataBuilder, Inputs } from '@mysten/sui/transactions';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { fromBase64, toBase64, toBase58 } from '@mysten/sui/utils';
import { blake2b } from '@noble/hashes/blake2.js';
import { messageWithIntent } from '@mysten/sui/cryptography';
import { bcs } from '@mysten/sui/bcs';
import { getZkLoginSignature } from '@mysten/sui/zklogin';

/**
 * Sponsored transaction tests — following the official Sui SDK documentation.
 * Reference: https://sdk.mystenlabs.com/sui/transactions/signing-and-execution#sponsored-transactions
 *
 * Two flows are documented:
 *   1. Coin-based sponsorship (sponsor provides specific gas coin objects)
 *   2. Address balance sponsorship (sponsor pays from address balance, empty gas payment)
 *
 * The current codebase uses Coin-based sponsorship.
 */

const USER_ADDRESS = '0x' + '11'.repeat(32);
const SPONSOR_ADDRESS = '0x' + '22'.repeat(32);
const TABLE_OBJECT_ID = '0x' + '33'.repeat(32);
const GAS_COIN_ID = '0x' + '44'.repeat(32);
// Valid base58-encoded 32-byte digests (object digests on Sui are base58)
const OBJ_DIGEST = toBase58(new Uint8Array(32).fill(0xcd));
const GAS_DIGEST = toBase58(new Uint8Array(32).fill(0xab));

/**
 * Build a TransactionKind BCS with pre-resolved owned object inputs.
 * This simulates the output of the backend's PTB builder (texas/src/relayer/ptb.rs).
 */
function buildKindBytesWithOwnedObject(): Uint8Array {
  const builder = new TransactionDataBuilder();
  builder.inputs = [
    Inputs.ObjectRef({ objectId: TABLE_OBJECT_ID, version: '1', digest: OBJ_DIGEST }),
    Inputs.Pure(bcs.Address.serialize(USER_ADDRESS).toBytes()),
  ];
  builder.commands = [
    {
      $kind: 'TransferObjects',
      TransferObjects: {
        objects: [{ $kind: 'Input', Input: 0 }],
        address: { $kind: 'Input', Input: 1 },
      },
    },
  ];
  return builder.build({ onlyTransactionKind: true });
}

/**
 * Build a TransactionKind BCS with a shared object input.
 * This simulates the backend's `shared_input` function which uses `initial_shared_version: 0`.
 */
function buildKindBytesWithSharedObject(initialSharedVersion: number | string = 1): Uint8Array {
  const builder = new TransactionDataBuilder();
  builder.inputs = [
    Inputs.SharedObjectRef({
      objectId: TABLE_OBJECT_ID,
      initialSharedVersion,
      mutable: false,
    }),
    Inputs.Pure(bcs.Address.serialize(USER_ADDRESS).toBytes()),
  ];
  builder.commands = [
    {
      $kind: 'TransferObjects',
      TransferObjects: {
        objects: [{ $kind: 'Input', Input: 0 }],
        address: { $kind: 'Input', Input: 1 },
      },
    },
  ];
  return builder.build({ onlyTransactionKind: true });
}

/**
 * Verify an Ed25519 signature against the transaction bytes.
 * This replicates what the Sui network does to verify signatures.
 */
async function verifySignature(txBytes: Uint8Array, signature: string): Promise<boolean> {
  const intentMessage = messageWithIntent('TransactionData', txBytes);
  const digest = blake2b(intentMessage, { dkLen: 32 });
  const sigBytes = fromBase64(signature);
  // Signature format: [scheme_flag (1 byte)] [signature (64 bytes)] [pubkey (32 bytes)]
  const sigRaw = sigBytes.slice(1, 65);
  const pubKey = sigBytes.slice(65, 97);
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  return ed25519.verify(sigRaw, digest, pubKey);
}

/**
 * Compute the transaction digest the same way the Sui network does.
 */
function computeTxDigest(txBytes: Uint8Array): string {
  const intentMessage = messageWithIntent('TransactionData', txBytes);
  const digest = blake2b(intentMessage, { dkLen: 32 });
  return toBase58(digest);
}

describe('Official sponsored transaction pattern (Coin-based sponsorship)', () => {
  /**
   * This test follows the EXACT pattern from the official docs:
   * https://sdk.mystenlabs.com/sui/transactions/signing-and-execution#coin-based-sponsorship
   *
   * Note: The official docs use `build({ client: grpcClient })` which auto-resolves
   * gas budget/price. In our codebase, we get gas info from the sponsor backend,
   * so we set gas budget/price explicitly and can build offline.
   */
  it('official coin-based sponsorship pattern: both signatures verify', async () => {
    // 1. User builds transaction kind bytes (no gas info)
    //    In the real flow, this comes from the backend's PTB builder
    const kindBytes = buildKindBytesWithOwnedObject();
    const kindB64 = toBase64(kindBytes);

    // 2. Sponsor wraps with gas info using Transaction.fromKind (official recommendation)
    const sponsoredTx = Transaction.fromKind(kindB64);
    sponsoredTx.setSender(USER_ADDRESS);
    sponsoredTx.setGasOwner(SPONSOR_ADDRESS);
    sponsoredTx.setGasBudget(50_000_000);
    sponsoredTx.setGasPrice(1000);
    sponsoredTx.setGasPayment([
      { objectId: GAS_COIN_ID, version: '1', digest: GAS_DIGEST },
    ]);

    // 3. Build the full transaction (offline, no client needed when gas info is set)
    const fullBytes = await sponsoredTx.build();

    // 4. Both parties sign the SAME bytes
    const userKeypair = Ed25519Keypair.generate();
    const sponsorKeypair = Ed25519Keypair.generate();
    const { signature: userSignature } = await userKeypair.signTransaction(fullBytes);
    const { signature: sponsorSignature } = await sponsorKeypair.signTransaction(fullBytes);

    // 5. Both signatures should verify against the same digest
    expect(await verifySignature(fullBytes, userSignature)).toBe(true);
    expect(await verifySignature(fullBytes, sponsorSignature)).toBe(true);

    // The digest is the same for both signatures (since they sign the same bytes)
    const digest = computeTxDigest(fullBytes);
    expect(digest).toBeTruthy();
  });
});

describe('Transaction.fromKind vs TransactionDataBuilder.fromKindBytes equivalence', () => {
  /**
   * This test verifies that the official pattern (Transaction.fromKind) produces
   * the same bytes as the previous pattern (TransactionDataBuilder.fromKindBytes).
   * This is important to ensure the refactoring doesn't change behavior.
   */
  it('both approaches produce identical bytes', async () => {
    const kindBytes = buildKindBytesWithOwnedObject();

    // Approach A: Transaction.fromKind (official recommendation)
    const txA = Transaction.fromKind(toBase64(kindBytes));
    txA.setSender(USER_ADDRESS);
    txA.setGasOwner(SPONSOR_ADDRESS);
    txA.setGasBudget(50_000_000);
    txA.setGasPrice(1000);
    txA.setGasPayment([
      { objectId: GAS_COIN_ID, version: '1', digest: GAS_DIGEST },
    ]);
    const bytesA = await txA.build();

    // Approach B: TransactionDataBuilder.fromKindBytes (previous approach)
    const builder = TransactionDataBuilder.fromKindBytes(kindBytes);
    builder.sender = USER_ADDRESS;
    builder.gasData = {
      budget: 50_000_000,
      price: '1000',
      owner: SPONSOR_ADDRESS,
      payment: [{ objectId: GAS_COIN_ID, version: '1', digest: GAS_DIGEST }],
    };
    const bytesB = builder.build();

    // Both approaches should produce identical bytes
    expect(toBase64(bytesA)).toBe(toBase64(bytesB));
  });

  it('gas_owner is correctly set to sponsor address (not sender)', async () => {
    const kindBytes = buildKindBytesWithOwnedObject();

    const sponsoredTx = Transaction.fromKind(toBase64(kindBytes));
    sponsoredTx.setSender(USER_ADDRESS);
    sponsoredTx.setGasOwner(SPONSOR_ADDRESS);
    sponsoredTx.setGasBudget(50_000_000);
    sponsoredTx.setGasPrice(1000);
    sponsoredTx.setGasPayment([
      { objectId: GAS_COIN_ID, version: '1', digest: GAS_DIGEST },
    ]);

    // Verify gas owner is set correctly before build
    const data = sponsoredTx.getData();
    expect(data.gasData.owner).toBe(SPONSOR_ADDRESS);
    expect(data.sender).toBe(USER_ADDRESS);

    const fullBytes = await sponsoredTx.build();
    expect(fullBytes.length).toBeGreaterThan(0);
  });
});

describe('Shared object handling (backend uses initialSharedVersion=0)', () => {
  /**
   * The backend's ptb.rs uses `initial_shared_version: 0` as a placeholder.
   * These tests verify that the signature still works with this placeholder.
   */
  it('shared object with initialSharedVersion=1: signature verifies', async () => {
    const kindBytes = buildKindBytesWithSharedObject(1);
    const kindB64 = toBase64(kindBytes);

    const sponsoredTx = Transaction.fromKind(kindB64);
    sponsoredTx.setSender(USER_ADDRESS);
    sponsoredTx.setGasOwner(SPONSOR_ADDRESS);
    sponsoredTx.setGasBudget(50_000_000);
    sponsoredTx.setGasPrice(1000);
    sponsoredTx.setGasPayment([
      { objectId: GAS_COIN_ID, version: '1', digest: GAS_DIGEST },
    ]);

    const fullBytes = await sponsoredTx.build();

    const keypair = Ed25519Keypair.generate();
    const { signature } = await keypair.signTransaction(fullBytes);
    expect(await verifySignature(fullBytes, signature)).toBe(true);
  });

  it('shared object with initialSharedVersion=0 (backend placeholder): signature verifies', async () => {
    const kindBytes = buildKindBytesWithSharedObject(0);
    const kindB64 = toBase64(kindBytes);

    const sponsoredTx = Transaction.fromKind(kindB64);
    sponsoredTx.setSender(USER_ADDRESS);
    sponsoredTx.setGasOwner(SPONSOR_ADDRESS);
    sponsoredTx.setGasBudget(50_000_000);
    sponsoredTx.setGasPrice(1000);
    sponsoredTx.setGasPayment([
      { objectId: GAS_COIN_ID, version: '1', digest: GAS_DIGEST },
    ]);

    const fullBytes = await sponsoredTx.build();

    const keypair = Ed25519Keypair.generate();
    const { signature } = await keypair.signTransaction(fullBytes);
    expect(await verifySignature(fullBytes, signature)).toBe(true);
  });
});

describe('zkLogin signature construction', () => {
  /**
   * Test that getZkLoginSignature correctly wraps the user signature.
   * This tests the signature format without needing a real zkProof.
   */
  it('getZkLoginSignature produces parseable signature with correct structure', async () => {
    const kindBytes = buildKindBytesWithOwnedObject();
    const sponsoredTx = Transaction.fromKind(toBase64(kindBytes));
    sponsoredTx.setSender(USER_ADDRESS);
    sponsoredTx.setGasOwner(SPONSOR_ADDRESS);
    sponsoredTx.setGasBudget(50_000_000);
    sponsoredTx.setGasPrice(1000);
    sponsoredTx.setGasPayment([
      { objectId: GAS_COIN_ID, version: '1', digest: GAS_DIGEST },
    ]);
    const fullBytes = await sponsoredTx.build();

    // Sign with ephemeral key
    const ephemeralKeypair = Ed25519Keypair.generate();
    const { signature: userSignature } = await ephemeralKeypair.signTransaction(fullBytes);

    // Construct zkLogin signature with a mock zkProof
    const mockZkProof = {
      proofPoints: {
        a: ['0', '0'],
        b: [['0'], ['0']],
        c: ['0', '0'],
      },
      issBase64Details: {
        value: 'mock_iss',
        indexMod4: 0,
      },
      headerBase64: 'mock_header',
    };

    const mockAddressSeed = '123456789';
    const mockMaxEpoch = 10;

    const zkLoginSignature = getZkLoginSignature({
      inputs: {
        ...mockZkProof,
        addressSeed: mockAddressSeed,
      },
      maxEpoch: mockMaxEpoch,
      userSignature,
    });

    // The zkLogin signature should be a valid base64 string
    expect(typeof zkLoginSignature).toBe('string');
    expect(zkLoginSignature.length).toBeGreaterThan(0);

    // The first byte should be the ZkLogin flag (0x05)
    const sigBytes = fromBase64(zkLoginSignature);
    expect(sigBytes[0]).toBe(0x05); // SIGNATURE_SCHEME_TO_FLAG.ZkLogin

    // The user signature should be embedded inside the zkLogin signature
    // We can't verify the zkProof (it's mock), but we can check the structure
    expect(sigBytes.length).toBeGreaterThan(100);
  });

  /**
   * Test that the same ephemeral key produces a valid signature that
   * matches the public key embedded in the signature.
   */
  it('ephemeral key signature contains matching public key', async () => {
    const ephemeralKeypair = Ed25519Keypair.generate();
    const txBytes = new Uint8Array([1, 2, 3, 4, 5]);

    const { signature } = await ephemeralKeypair.signTransaction(txBytes);
    const sigBytes = fromBase64(signature);

    // Extract public key from signature (bytes 65-97)
    const pubKeyFromSig = sigBytes.slice(65, 97);
    const expectedPubKey = ephemeralKeypair.getPublicKey().toRawBytes();

    expect(Array.from(pubKeyFromSig)).toEqual(Array.from(expectedPubKey));
  });
});

describe('Full sponsored transaction flow simulation', () => {
  /**
   * This test simulates the full flow without network calls:
   * 1. Backend builds TransactionKind
   * 2. Frontend rehydrates with Transaction.fromKind
   * 3. Frontend sets gas info
   * 4. Frontend builds full tx bytes
   * 5. Frontend signs with ephemeral key
   * 6. Sponsor signs the same bytes
   * 7. Both signatures verify
   */
  it('full flow: backend kind → frontend build → dual signatures verify', async () => {
    // Step 1: Backend builds TransactionKind (simulated)
    const kindBytes = buildKindBytesWithOwnedObject();
    const kindB64 = toBase64(kindBytes);

    // Step 2: Frontend rehydrates with Transaction.fromKind
    const sponsoredTx = Transaction.fromKind(kindB64);

    // Step 3: Set gas info (from sponsor's gas-info endpoint)
    sponsoredTx.setSender(USER_ADDRESS);
    sponsoredTx.setGasOwner(SPONSOR_ADDRESS);
    sponsoredTx.setGasBudget(50_000_000);
    sponsoredTx.setGasPrice(1000);
    sponsoredTx.setGasPayment([
      { objectId: GAS_COIN_ID, version: '1', digest: GAS_DIGEST },
    ]);

    // Step 4: Build full tx bytes
    const txBytes = await sponsoredTx.build();
    const txBytesB64 = toBase64(txBytes);

    // Step 5: User (ephemeral key) signs
    const userKeypair = Ed25519Keypair.generate();
    const { signature: userSignature } = await userKeypair.signTransaction(txBytes);

    // Step 6: Sponsor signs the SAME bytes
    const sponsorKeypair = Ed25519Keypair.generate();
    const { signature: sponsorSignature } = await sponsorKeypair.signTransaction(txBytes);

    // Step 7: Both signatures verify against the same tx bytes
    expect(await verifySignature(txBytes, userSignature)).toBe(true);
    expect(await verifySignature(txBytes, sponsorSignature)).toBe(true);

    // The txBytesB64 is what gets sent to the sponsor's /transaction endpoint
    expect(txBytesB64).toBeTruthy();
    expect(typeof txBytesB64).toBe('string');
  });

  /**
   * Test that the txBytesB64 sent to sponsor is the same as what was signed.
   * This is critical: if they differ, the sponsor's signature won't match.
   */
  it('txBytesB64 sent to sponsor matches signed bytes', async () => {
    const kindBytes = buildKindBytesWithOwnedObject();
    const sponsoredTx = Transaction.fromKind(toBase64(kindBytes));
    sponsoredTx.setSender(USER_ADDRESS);
    sponsoredTx.setGasOwner(SPONSOR_ADDRESS);
    sponsoredTx.setGasBudget(50_000_000);
    sponsoredTx.setGasPrice(1000);
    sponsoredTx.setGasPayment([
      { objectId: GAS_COIN_ID, version: '1', digest: GAS_DIGEST },
    ]);

    const txBytes = await sponsoredTx.build();
    const txBytesB64 = toBase64(txBytes);

    // The base64-encoded bytes should decode back to the same bytes
    const decoded = fromBase64(txBytesB64);
    expect(toBase64(decoded)).toBe(txBytesB64);
    expect(Array.from(decoded)).toEqual(Array.from(txBytes));
  });
});
