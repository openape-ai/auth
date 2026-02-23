import type { KeyLike } from 'jose'

export interface CodeEntry {
  code: string
  spId: string
  redirectUri: string
  codeChallenge: string
  userId: string
  nonce: string
  expiresAt: number
}

export interface ConsentEntry {
  userId: string
  spId: string
  grantedAt: number
}

export interface CodeStore {
  save: (entry: CodeEntry) => Promise<void>
  find: (code: string) => Promise<CodeEntry | null>
  delete: (code: string) => Promise<void>
}

export interface ConsentStore {
  hasConsent: (userId: string, spId: string) => Promise<boolean>
  save: (entry: ConsentEntry) => Promise<void>
}

export interface KeyEntry {
  kid: string
  privateKey: KeyLike
  publicKey: KeyLike
}

export interface KeyStore {
  getSigningKey: () => Promise<KeyEntry>
  getAllPublicKeys: () => Promise<KeyEntry[]>
}

// In-memory implementations

export class InMemoryCodeStore implements CodeStore {
  private codes = new Map<string, CodeEntry>()

  async save(entry: CodeEntry): Promise<void> {
    this.codes.set(entry.code, entry)
  }

  async find(code: string): Promise<CodeEntry | null> {
    const entry = this.codes.get(code)
    if (!entry)
      return null
    if (entry.expiresAt < Date.now()) {
      this.codes.delete(code)
      return null
    }
    return entry
  }

  async delete(code: string): Promise<void> {
    this.codes.delete(code)
  }
}

export class InMemoryConsentStore implements ConsentStore {
  private consents = new Map<string, ConsentEntry>()

  private key(userId: string, spId: string): string {
    return `${userId}:${spId}`
  }

  async hasConsent(userId: string, spId: string): Promise<boolean> {
    return this.consents.has(this.key(userId, spId))
  }

  async save(entry: ConsentEntry): Promise<void> {
    this.consents.set(this.key(entry.userId, entry.spId), entry)
  }
}

export class InMemoryKeyStore implements KeyStore {
  private keys: KeyEntry[] = []
  private initialized = false

  async getSigningKey(): Promise<KeyEntry> {
    await this.ensureKeys()
    return this.keys[0]
  }

  async getAllPublicKeys(): Promise<KeyEntry[]> {
    await this.ensureKeys()
    return this.keys
  }

  private async ensureKeys(): Promise<void> {
    if (this.initialized)
      return
    const { generateKeyPair } = await import('@openape/core')
    const { publicKey, privateKey } = await generateKeyPair()
    this.keys.push({ kid: 'key-1', publicKey, privateKey })
    this.initialized = true
  }
}
