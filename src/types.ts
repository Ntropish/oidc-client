export interface OidcUser {
  sub: string;
  preferred_username?: string;
  name?: string;
  picture?: string;
  groups?: string[];
}

export interface OidcTokens {
  accessToken: string;
  refreshToken: string;
  idToken: string;
  expiresAt: number;
}
