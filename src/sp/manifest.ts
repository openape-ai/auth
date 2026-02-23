import type { SPManifest } from '@openape/core'

/**
 * Generate an SP Manifest JSON object.
 */
export function createSPManifest(config: SPManifest): SPManifest {
  return { ...config }
}

/**
 * Create a Response object serving the SP Manifest as JSON.
 */
export function serveSPManifest(config: SPManifest): Response {
  return new Response(JSON.stringify(config, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=3600',
    },
  })
}
