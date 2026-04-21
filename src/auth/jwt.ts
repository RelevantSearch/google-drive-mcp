/**
 * HS256 JWT sign/verify using `jose`.
 *
 * Stateless 1-hour access tokens issued to claude.ai.
 * requireBearerAuth checks expiresAt on every request.
 */

import { SignJWT, jwtVerify } from 'jose';

export interface McpJwtPayload {
  sub: string;
  email: string;
  scope: string;
  exp: number;
}

export class McpJwt {
  private readonly secret: Uint8Array;

  /**
   * @param secretKey — raw secret string (from env or Secret Manager).
   *   Encoded to Uint8Array for jose HS256.
   */
  constructor(secretKey: string) {
    this.secret = new TextEncoder().encode(secretKey);
  }

  /**
   * Signs a JWT with sub, email, scope. Expires in 3600 seconds.
   */
  async sign(payload: {
    sub: string;
    email: string;
    scope: string;
  }): Promise<string> {
    return new SignJWT({
      sub: payload.sub,
      email: payload.email,
      scope: payload.scope,
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('3600s')
      .sign(this.secret);
  }

  /**
   * Verifies a JWT and returns the payload.
   * Throws on invalid signature or expired token.
   */
  async verify(token: string): Promise<McpJwtPayload> {
    const { payload } = await jwtVerify(token, this.secret);
    return {
      sub: payload.sub as string,
      email: payload.email as string,
      scope: payload.scope as string,
      exp: payload.exp as number,
    };
  }
}
