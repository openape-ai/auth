import { describe, expect, it } from 'vitest'
import { createSPManifest, serveSPManifest } from '../sp/manifest.js'

describe('sP Manifest', () => {
  const config = {
    sp_id: 'sp.example.com',
    name: 'Example SP',
    redirect_uris: ['https://sp.example.com/callback'],
  }

  it('creates a manifest object', () => {
    const manifest = createSPManifest(config)
    expect(manifest.sp_id).toBe('sp.example.com')
    expect(manifest.name).toBe('Example SP')
  })

  it('serves manifest as JSON response', () => {
    const response = serveSPManifest(config)
    expect(response.headers.get('Content-Type')).toBe('application/json')
  })
})
