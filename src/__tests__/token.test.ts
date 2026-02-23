import { generateCodeChallenge, generateCodeVerifier, verifyJWT } from '@openape/core'
import { describe, expect, it } from 'vitest'
import { InMemoryCodeStore, InMemoryKeyStore } from '../idp/stores.js'
import { handleTokenExchange } from '../idp/token.js'

describe('handleTokenExchange', () => {
  it('exchanges a valid code for an assertion', async () => {
    const codeStore = new InMemoryCodeStore()
    const keyStore = new InMemoryKeyStore()
    const verifier = generateCodeVerifier()
    const challenge = await generateCodeChallenge(verifier)

    await codeStore.save({
      code: 'test-code',
      spId: 'sp.example.com',
      redirectUri: 'https://sp.example.com/callback',
      codeChallenge: challenge,
      userId: 'alice@example.com',
      nonce: 'test-nonce',
      expiresAt: Date.now() + 60000,
    })

    const result = await handleTokenExchange(
      {
        grant_type: 'authorization_code',
        code: 'test-code',
        code_verifier: verifier,
        redirect_uri: 'https://sp.example.com/callback',
        sp_id: 'sp.example.com',
      },
      codeStore,
      keyStore,
      'https://idp.example.com',
    )

    expect(result.assertion).toBeTruthy()
    expect(result.assertion.split('.')).toHaveLength(3)

    // Verify the assertion contents
    const key = await keyStore.getSigningKey()
    const { payload } = await verifyJWT(result.assertion, key.publicKey)
    expect(payload.iss).toBe('https://idp.example.com')
    expect(payload.sub).toBe('alice@example.com')
    expect(payload.aud).toBe('sp.example.com')
    expect(payload.act).toBe('human')
    expect(payload.nonce).toBe('test-nonce')
  })

  it('rejects invalid code', async () => {
    const codeStore = new InMemoryCodeStore()
    const keyStore = new InMemoryKeyStore()

    await expect(handleTokenExchange(
      {
        grant_type: 'authorization_code',
        code: 'invalid',
        code_verifier: 'v',
        redirect_uri: 'https://sp/cb',
        sp_id: 'sp',
      },
      codeStore,
      keyStore,
      'https://idp',
    )).rejects.toThrow('Invalid or expired')
  })

  it('rejects wrong PKCE verifier', async () => {
    const codeStore = new InMemoryCodeStore()
    const keyStore = new InMemoryKeyStore()
    const verifier = generateCodeVerifier()
    const challenge = await generateCodeChallenge(verifier)

    await codeStore.save({
      code: 'test-code',
      spId: 'sp',
      redirectUri: 'https://sp/cb',
      codeChallenge: challenge,
      userId: 'alice@example.com',
      nonce: 'n',
      expiresAt: Date.now() + 60000,
    })

    await expect(handleTokenExchange(
      {
        grant_type: 'authorization_code',
        code: 'test-code',
        code_verifier: 'wrong-verifier',
        redirect_uri: 'https://sp/cb',
        sp_id: 'sp',
      },
      codeStore,
      keyStore,
      'https://idp',
    )).rejects.toThrow('PKCE')
  })
})
