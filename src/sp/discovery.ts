import type { DDISARecord, ResolverOptions } from '@openape/core'
import { extractDomain, resolveDDISA } from '@openape/core'

export interface IdPConfig {
  idpUrl: string
  mode?: string
  record: DDISARecord
}

/**
 * Discover the IdP for a given email address.
 */
export async function discoverIdP(
  email: string,
  options?: ResolverOptions,
): Promise<IdPConfig | null> {
  const domain = extractDomain(email)
  const record = await resolveDDISA(domain, options)

  if (!record)
    return null

  return {
    idpUrl: record.idp,
    mode: record.mode,
    record,
  }
}
