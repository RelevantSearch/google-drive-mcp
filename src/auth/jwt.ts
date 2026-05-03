/**
 * HS256 JWT sign/verify using `jose`.
 *
 * Stateless 1-hour access tokens issued to claude.ai.
 * requireBearerAuth checks expiresAt on every request.
 */

import { SignJWT, jwtVerify, errors as joseErrors } from 'jose';

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

  /**
   * Verifies signature; returns payload even if `exp` has passed.
   * Throws on bad signature or any other validation failure.
   * Used by token revocation per RFC 7009 to revoke chains for
   * recently-expired access tokens.
   */
  async verifyAllowExpired(token: string): Promise<McpJwtPayload> {
    try {
      return await this.verify(token);
    } catch (err) {
      if (err instanceof joseErrors.JWTExpired) {
        // Signature was valid (jose checks sig before exp); decode the payload
        // with an effectively-infinite clock tolerance to skip the exp check.
        const { payload } = await jwtVerify(token, this.secret, {
          clockTolerance: '100y',
        });
        return {
          sub: payload.sub as string,
          email: payload.email as string,
          scope: payload.scope as string,
          exp: payload.exp as number,
        };
      }
      throw err;
    }
  }
}
