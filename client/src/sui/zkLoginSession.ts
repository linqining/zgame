import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import {
  generateNonce,
  generateRandomness,
  getExtendedEphemeralPublicKey,
  jwtToAddress,
  getZkLoginSignature,
  genAddressSeed,
  decodeJwt,
} from '@mysten/sui/zklogin';
import { Transaction } from '@mysten/sui/transactions';

// Base64 helpers (replacing removed fromB64/toB64 from @mysten/sui/utils)
function fromB64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function toB64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// zkLogin session state
export interface ZkLoginSession {
  ephemeralKeyPair: Ed25519Keypair;
  maxEpoch: number;
  randomness: string;
  jwt: string;
  zkProof: ZkProof;
  userSalt: string;
  address: string;
  decodedJwt: DecodedJwt;
}

export interface ZkProof {
  proofPoints: {
    a: string[];
    b: string[][];
    c: string[];
  };
  issBase64Details: {
    value: string;
    indexMod4: number;
  };
  headerBase64: string;
}

export interface DecodedJwt {
  iss: string;
  sub: string;
  aud: string;
  exp?: number;
  iat?: number;
  email?: string;
}

// Serialized session for localStorage persistence
interface SerializedSession {
  ephemeralSecretKey: string;
  maxEpoch: number;
  randomness: string;
  jwt: string;
  zkProof: ZkProof;
  userSalt: string;
  address: string;
  decodedJwt: DecodedJwt;
}

const SESSION_STORAGE_KEY = 'zklogin_session';
const PROVER_URLS: Record<string, string> = {
  devnet: 'https://prover-dev.mystenlabs.com/v1',
  testnet: 'https://prover-dev.mystenlabs.com/v1',
  mainnet: 'https://prover.mainnet.mystenlabs.com/v1',
};

// OAuth provider configurations
export interface OAuthProviderConfig {
  clientId: string;
  redirectUrl: string;
  authUrl: string;
  scope: string;
}

export const OAUTH_PROVIDERS: Record<string, (clientId: string, redirectUrl: string) => OAuthProviderConfig> = {
  google: (clientId, redirectUrl) => ({
    clientId,
    redirectUrl,
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    scope: 'openid email profile',
  }),
  apple: (clientId, redirectUrl) => ({
    clientId,
    redirectUrl,
    authUrl: 'https://appleid.apple.com/auth/authorize',
    scope: 'openid email',
  }),
  facebook: (clientId, redirectUrl) => ({
    clientId,
    redirectUrl,
    authUrl: 'https://www.facebook.com/v19.0/dialog/oauth',
    scope: 'openid email',
  }),
  twitch: (clientId, redirectUrl) => ({
    clientId,
    redirectUrl,
    authUrl: 'https://id.twitch.tv/oauth2/authorize',
    scope: 'openid user:read:email',
  }),
};

export class ZkLoginSessionManager {
  private session: ZkLoginSession | null = null;
  private client: SuiGrpcClient;
  private network: string;
  private saltServiceUrl: string;

  constructor(client: SuiGrpcClient, network: string = 'testnet', saltServiceUrl?: string) {
    this.client = client;
    this.network = network;
    this.saltServiceUrl = saltServiceUrl || '/api/auth/zklogin/salt';
    this.loadSession();
  }

  // Step 1: Generate ephemeral keypair and prepare OAuth URL
  async prepareOAuthUrl(
    provider: string,
    clientId: string,
    redirectUrl: string,
  ): Promise<{ url: string; nonce: string }> {
    const ephemeralKeyPair = Ed25519Keypair.generate();
    const randomness = generateRandomness();

    // Get current epoch
    const { systemState } = await this.client.core.getCurrentSystemState();
    const epoch = systemState.epoch;
    const maxEpoch = Number(epoch) + 2;

    const nonce = generateNonce(ephemeralKeyPair.getPublicKey(), maxEpoch, randomness);

    // Store ephemeral data temporarily for callback processing
    sessionStorage.setItem('zk_ephemeral_secret', ephemeralKeyPair.getSecretKey());
    sessionStorage.setItem('zk_maxEpoch', String(maxEpoch));
    sessionStorage.setItem('zk_randomness', randomness);
    sessionStorage.setItem('zk_provider', provider);

    const providerConfig = OAUTH_PROVIDERS[provider](clientId, redirectUrl);
    const params = new URLSearchParams({
      client_id: providerConfig.clientId,
      redirect_uri: providerConfig.redirectUrl,
      response_type: 'id_token',
      scope: providerConfig.scope,
      nonce,
    });

    // Provider-specific params
    if (provider === 'google') {
      // Google implicit flow: response_type=id_token returns id_token in hash fragment
      params.set('prompt', 'consent');
    } else if (provider === 'twitch') {
      // Twitch requires force_verify for zkLogin
      params.set('force_verify', 'true');
    } else if (provider === 'apple') {
      // Apple requires response_mode form_post for id_token
      params.set('response_mode', 'form_post');
    }

    const url = `${providerConfig.authUrl}?${params}`;
    console.log('[zkLogin] OAuth URL:', url);
    console.log('[zkLogin] redirect_uri:', providerConfig.redirectUrl);
    console.log('[zkLogin] client_id:', providerConfig.clientId);
    console.log('[zkLogin] nonce:', nonce);
    return { url, nonce };
  }

  // Step 2: Process OAuth callback - extract JWT and create session
  async handleCallback(jwt: string): Promise<ZkLoginSession> {
    const ephemeralSecretKey = sessionStorage.getItem('zk_ephemeral_secret');
    const maxEpochStr = sessionStorage.getItem('zk_maxEpoch');
    const randomness = sessionStorage.getItem('zk_randomness');

    if (!ephemeralSecretKey || !maxEpochStr || !randomness) {
      throw new Error('Missing ephemeral key data. Please restart the login flow.');
    }

    const ephemeralKeyPair = Ed25519Keypair.fromSecretKey(ephemeralSecretKey);
    const maxEpoch = Number(maxEpochStr);

    // Decode JWT
    const decodedJwt = decodeJwt(jwt);

    // Fetch user salt from backend
    const userSalt = await this.fetchUserSalt(jwt);

    // Get ZK proof from prover
    const extendedEphemeralPublicKey = getExtendedEphemeralPublicKey(
      ephemeralKeyPair.getPublicKey(),
    );

    const zkProof = await this.fetchZkProof({
      jwt,
      extendedEphemeralPublicKey,
      maxEpoch,
      jwtRandomness: randomness,
      salt: userSalt,
      keyClaimName: 'sub',
    });

    // Derive address
    const address = jwtToAddress(jwt, userSalt, false);

    this.session = {
      ephemeralKeyPair,
      maxEpoch,
      randomness,
      jwt,
      zkProof,
      userSalt,
      address,
      decodedJwt,
    };

    // Persist session
    this.saveSession();

    // Clean up temporary storage
    sessionStorage.removeItem('zk_ephemeral_secret');
    sessionStorage.removeItem('zk_maxEpoch');
    sessionStorage.removeItem('zk_randomness');
    sessionStorage.removeItem('zk_provider');

    return this.session!;
  }

  // Sign a transaction with zkLogin (no wallet popup!)
  async signTransaction(transaction: Transaction): Promise<{
    signature: string;
    txBytes: string;
  }> {
    if (!this.session) {
      throw new Error('No active zkLogin session. Please login first.');
    }

    // Check if session is still valid
    const { systemState } = await this.client.core.getCurrentSystemState();
    const currentEpoch = Number(systemState.epoch);
    if (currentEpoch > this.session.maxEpoch) {
      this.clearSession();
      throw new Error('zkLogin session expired. Please login again.');
    }

    transaction.setSender(this.session.address);
    const txBytes = await transaction.build({ client: this.client });

    // Sign with ephemeral key (local, no popup)
    const { signature: userSignature } = await this.session.ephemeralKeyPair.signTransaction(txBytes);

    // Compose zkLogin signature
    const addressSeed = genAddressSeed(
      this.session.userSalt,
      'sub',
      this.session.decodedJwt.sub,
      this.session.decodedJwt.aud,
    );

    const zkLoginSignature = getZkLoginSignature({
      inputs: {
        ...this.session.zkProof,
        addressSeed: addressSeed.toString(),
      },
      maxEpoch: this.session.maxEpoch,
      userSignature,
    });

    return {
      signature: zkLoginSignature,
      txBytes: toB64(txBytes),
    };
  }

  // Execute a transaction (sign + submit)
  async executeTransaction(transaction: Transaction): Promise<string> {
    const { signature, txBytes } = await this.signTransaction(transaction);

    const result = await this.client.executeTransaction({
      transaction: fromB64(txBytes),
      signatures: [signature],
      include: {
        effects: true,
      },
    });

    if (result.$kind === 'FailedTransaction') {
      const tx = result.FailedTransaction!;
      throw new Error(`Transaction failed: ${tx.effects?.status?.error?.message || 'Unknown error'}`);
    }

    const tx = result.Transaction!;
    if (!tx.effects?.status?.success) {
      throw new Error(`Transaction failed: ${tx.effects?.status?.error?.message || 'Unknown error'}`);
    }

    return tx.digest ?? '';
  }

  // Fetch user salt from backend salt service
  private async fetchUserSalt(jwt: string): Promise<string> {
    const response = await fetch(this.saltServiceUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jwt }),
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch salt: ${response.statusText}`);
    }

    const data = await response.json();
    return data.salt;
  }

  // Fetch ZK proof from Mysten Labs prover
  private async fetchZkProof(params: {
    jwt: string;
    extendedEphemeralPublicKey: string;
    maxEpoch: number;
    jwtRandomness: string;
    salt: string;
    keyClaimName: string;
  }): Promise<ZkProof> {
    const proverUrl = PROVER_URLS[this.network] || PROVER_URLS.testnet;

    // Prover API requires maxEpoch as string, not number
    const body = {
      ...params,
      maxEpoch: String(params.maxEpoch),
    };

    console.log('[zkLogin] Fetching ZK proof from:', proverUrl);

    const response = await fetch(proverUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      console.error('[zkLogin] Prover error:', response.status, errorText);
      throw new Error(`Failed to fetch ZK proof: ${response.statusText} ${errorText}`);
    }

    return response.json();
  }

  // Persist session to localStorage
  private saveSession(): void {
    if (!this.session) return;

    const serialized: SerializedSession = {
      ephemeralSecretKey: this.session.ephemeralKeyPair.getSecretKey(),
      maxEpoch: this.session.maxEpoch,
      randomness: this.session.randomness,
      jwt: this.session.jwt,
      zkProof: this.session.zkProof,
      userSalt: this.session.userSalt,
      address: this.session.address,
      decodedJwt: this.session.decodedJwt,
    };

    localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(serialized));
  }

  // Load session from localStorage
  private loadSession(): void {
    const stored = localStorage.getItem(SESSION_STORAGE_KEY);
    if (!stored) return;

    try {
      const serialized: SerializedSession = JSON.parse(stored);
      this.session = {
        ephemeralKeyPair: Ed25519Keypair.fromSecretKey(serialized.ephemeralSecretKey),
        maxEpoch: serialized.maxEpoch,
        randomness: serialized.randomness,
        jwt: serialized.jwt,
        zkProof: serialized.zkProof,
        userSalt: serialized.userSalt,
        address: serialized.address,
        decodedJwt: serialized.decodedJwt,
      };
    } catch (e) {
      console.error('[ZkLoginSession] Failed to load session:', e);
      localStorage.removeItem(SESSION_STORAGE_KEY);
    }
  }

  // Clear current session
  clearSession(): void {
    this.session = null;
    localStorage.removeItem(SESSION_STORAGE_KEY);
  }

  // Get current session
  getSession(): ZkLoginSession | null {
    return this.session;
  }

  // Check if session is active and valid
  async isSessionValid(): Promise<boolean> {
    if (!this.session) return false;

    try {
      const { systemState } = await this.client.core.getCurrentSystemState();
      const currentEpoch = Number(systemState.epoch);
      return currentEpoch <= this.session.maxEpoch;
    } catch {
      return false;
    }
  }

  // Get the zkLogin address
  get address(): string | null {
    return this.session?.address ?? null;
  }
}

// Singleton instance - initialized with the dAppKit client
let _instance: ZkLoginSessionManager | null = null;

export function getZkLoginSessionManager(
  client?: SuiGrpcClient,
  network?: string,
  saltServiceUrl?: string,
): ZkLoginSessionManager {
  if (!_instance && client) {
    _instance = new ZkLoginSessionManager(client, network, saltServiceUrl);
  }
  if (!_instance) {
    throw new Error('ZkLoginSessionManager not initialized. Call with client first.');
  }
  return _instance;
}

export function initZkLoginSessionManager(
  client: SuiGrpcClient,
  network: string = 'testnet',
  saltServiceUrl?: string,
): ZkLoginSessionManager {
  _instance = new ZkLoginSessionManager(client, network, saltServiceUrl);
  return _instance;
}
