import { generateVerifier, generateChallenge } from './pkce';
import type { OidcUser, OidcTokens } from './types';

export interface OidcClientOptions {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
  storage?: Storage;
}

interface OidcDiscovery {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  end_session_endpoint?: string;
  jwks_uri: string;
}

const STORAGE_KEYS = {
  accessToken: 'oidc:access_token',
  refreshToken: 'oidc:refresh_token',
  idToken: 'oidc:id_token',
  tokenExpiry: 'oidc:token_expiry',
} as const;

const PKCE_VERIFIER_KEY = 'oidc:pkce_verifier';

export class OidcClient {
  private issuer: string;
  private clientId: string;
  private redirectUri: string;
  private scope: string;
  private storage: Storage;
  private discovery: OidcDiscovery | null = null;

  constructor(options: OidcClientOptions) {
    this.issuer = options.issuer.replace(/\/$/, '');
    this.clientId = options.clientId;
    this.redirectUri = options.redirectUri;
    this.scope = options.scope ?? 'openid profile groups';
    this.storage = options.storage ?? localStorage;
  }

  private async getDiscovery(): Promise<OidcDiscovery> {
    if (this.discovery) return this.discovery;
    const res = await fetch(`${this.issuer}/.well-known/openid-configuration`);
    if (!res.ok) throw new Error(`Failed to fetch OIDC discovery: ${res.status}`);
    this.discovery = await res.json();
    return this.discovery!;
  }

  async login(): Promise<void> {
    const discovery = await this.getDiscovery();
    const verifier = generateVerifier();
    const challenge = await generateChallenge(verifier);

    sessionStorage.setItem(PKCE_VERIFIER_KEY, verifier);

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: this.scope,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });

    window.location.href = `${discovery.authorization_endpoint}?${params}`;
  }

  async handleCallback(): Promise<OidcUser> {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    if (!code) throw new Error('No authorization code in URL');

    const verifier = sessionStorage.getItem(PKCE_VERIFIER_KEY);
    if (!verifier) throw new Error('No PKCE verifier found');

    const discovery = await this.getDiscovery();

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      code,
      code_verifier: verifier,
    });

    const res = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Token exchange failed: ${res.status} ${text}`);
    }

    const data = await res.json();
    this.storeTokens(data);
    sessionStorage.removeItem(PKCE_VERIFIER_KEY);

    // Clean up the URL
    window.history.replaceState({}, '', window.location.pathname);

    return this.getUser()!;
  }

  async getAccessToken(): Promise<string> {
    const expiry = Number(this.storage.getItem(STORAGE_KEYS.tokenExpiry) ?? '0');
    const now = Date.now();

    // Refresh if within 60 seconds of expiry
    if (now >= expiry - 60_000) {
      await this.refreshToken();
    }

    const token = this.storage.getItem(STORAGE_KEYS.accessToken);
    if (!token) throw new Error('No access token available');
    return token;
  }

  async refreshToken(): Promise<void> {
    const refreshToken = this.storage.getItem(STORAGE_KEYS.refreshToken);
    if (!refreshToken) throw new Error('No refresh token available');

    const discovery = await this.getDiscovery();

    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: this.clientId,
      refresh_token: refreshToken,
    });

    const res = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });

    if (!res.ok) {
      // Refresh failed — clear tokens and throw
      this.clearTokens();
      throw new Error(`Token refresh failed: ${res.status}`);
    }

    const data = await res.json();
    this.storeTokens(data);
  }

  getUser(): OidcUser | null {
    const idToken = this.storage.getItem(STORAGE_KEYS.idToken);
    if (!idToken) return null;

    try {
      const payload = idToken.split('.')[1];
      const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
      return JSON.parse(decoded);
    } catch {
      return null;
    }
  }

  async logout(redirectTo?: string): Promise<void> {
    this.clearTokens();
    if (redirectTo) {
      window.location.href = redirectTo;
    }
  }

  isAuthenticated(): boolean {
    const token = this.storage.getItem(STORAGE_KEYS.accessToken);
    const expiry = Number(this.storage.getItem(STORAGE_KEYS.tokenExpiry) ?? '0');
    return !!token && Date.now() < expiry;
  }

  private storeTokens(data: {
    access_token: string;
    refresh_token: string;
    id_token: string;
    expires_in: number;
  }): void {
    this.storage.setItem(STORAGE_KEYS.accessToken, data.access_token);
    this.storage.setItem(STORAGE_KEYS.refreshToken, data.refresh_token);
    this.storage.setItem(STORAGE_KEYS.idToken, data.id_token);
    this.storage.setItem(
      STORAGE_KEYS.tokenExpiry,
      String(Date.now() + data.expires_in * 1000)
    );
  }

  private clearTokens(): void {
    this.storage.removeItem(STORAGE_KEYS.accessToken);
    this.storage.removeItem(STORAGE_KEYS.refreshToken);
    this.storage.removeItem(STORAGE_KEYS.idToken);
    this.storage.removeItem(STORAGE_KEYS.tokenExpiry);
  }
}
