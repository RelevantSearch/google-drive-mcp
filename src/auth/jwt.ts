/**
 * HS256 JWT sign/verify using `jose`.
 *
 * Stateless 1-hour access tokens issued to claude.ai.
 * requireBearerAuth checks expiresAt on every request.
 */

import { SignJWT, jwtVerify, decodeJwt, errors as joseErrors } from 'jose';

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
        // exp has passed but the signature was already validated by the
        // initial `verify()` call (jose checks sig before claims). To skip
        // only the exp check while still enforcing nbf and other claims,
        // re-verify with `currentDate` set to just after the JWT's iat.
        // Using `clockTolerance: '100y'` would also relax nbf, which is a
        // small but real attack surface (clock-skewed forged token).
        // `decodeJwt` parses the payload without verifying the signature;
        // the signature is verified by the subsequent `jwtVerify` call.
        const unverified = decodeJwt(token);
        const iat =
          typeof unverified.iat === 'number'
            ? unverified.iat
            : Math.floor(Date.now() / 1000);
        const { payload } = await jwtVerify(token, this.secret, {
          currentDate: new Date((iat + 1) * 1000),
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
