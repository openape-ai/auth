import type { DDISAAssertionClaims } from '@openape/core'
import type { JWTPayload } from 'jose'
import type { CodeStore, KeyStore } from './stores.js'
import { generateCodeChallenge, signJWT } from '@openape/core'

export interface TokenExchangeParams {
  grant_type: string
  code: string
  code_verifier: string
  redirect_uri: string
  sp_id: string
}

export interface TokenExchangeResult {
  assertion: string
}

/**
 * Handle token exchange: validate code + PKCE, issue assertion.
 */
export async function handleTokenExchange(
  params: TokenExchangeParams,
  codeStore: CodeStore,
  keyStore: KeyStore,
  issuer: string,
): Promise<TokenExchangeResult> {
  // Validate grant_type
  if (params.grant_type !== 'authorization_code') {
    throw new Error('Unsupported grant_type')
  }

  // Find the code
  const codeEntry = await codeStore.find(params.code)
  if (!codeEntry) {
    throw new Error('Invalid or expired authorization code')
  }

  // Validate SP ID
  if (codeEntry.spId !== params.sp_id) {
    throw new Error('SP ID mismatch')
  }

  // Validate redirect URI
  if (codeEntry.redirectUri !== params.redirect_uri) {
    throw new Error('Redirect URI mismatch')
  }

  // Validate PKCE
  const computedChallenge = await generateCodeChallenge(params.code_verifier)
  if (computedChallenge !== codeEntry.codeChallenge) {
    throw new Error('PKCE verification failed')
  }

  // Delete the code (single use)
  await codeStore.delete(params.code)

  // Issue assertion
  const assertion = await issueAssertion(
    {
      sub: codeEntry.userId,
      aud: params.sp_id,
      nonce: codeEntry.nonce,
    },
    keyStore,
    issuer,
  )

  return { assertion }
}

/**
 * Create and sign an assertion JWT.
 */
export async function issueAssertion(
  claims: { sub: string, aud: string, nonce: string },
  keyStore: KeyStore,
  issuer: string,
): Promise<string> {
  const key = await keyStore.getSigningKey()
  const now = Math.floor(Date.now() / 1000)

  const payload: DDISAAssertionClaims = {
    iss: issuer,
    sub: claims.sub,
    aud: claims.aud,
    iat: now,
    exp: now + 300, // 5 minutes max
    nonce: claims.nonce,
    jti: crypto.randomUUID(),
  }

  return signJWT(payload as unknown as JWTPayload, key.privateKey, { kid: key.kid })
}
