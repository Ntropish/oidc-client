export interface OidcUser {
  sub: string;
  display_name?: string;
  username?: string;
  avatar_url?: string;
  groups?: string[];
}

export interface OidcTokens {
  accessToken: string;
  refreshToken: string;
  idToken: string;
  expiresAt: number;
}
