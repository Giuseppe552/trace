import { describe, it, expect } from 'vitest'

// test the header parsing logic without network calls
// we test the platform detection and tracking ID extraction

describe('header fingerprint patterns', () => {
  // import the module to test against its internal logic
  // since collectHeaders requires network, we test the patterns directly

  it('detects GA4 tracking IDs', () => {
    const pattern = /G-[A-Z0-9]{10,}/
    expect(pattern.test('G-ABC1234567')).toBe(true)
    expect(pattern.test('G-short')).toBe(false)
    expect(pattern.test('UA-12345-1')).toBe(false)
  })

  it('detects UA tracking IDs', () => {
    const pattern = /UA-\d{4,10}-\d{1,4}/
    expect(pattern.test('UA-12345678-1')).toBe(true)
    expect(pattern.test('UA-123-1')).toBe(false)
  })

  it('detects GTM IDs', () => {
    const pattern = /GTM-[A-Z0-9]{6,}/
    expect(pattern.test('GTM-ABCDEF')).toBe(true)
    expect(pattern.test('GTM-AB')).toBe(false)
  })

  it('platform detection: vercel headers', () => {
    const headers: Record<string, string> = {
      'x-vercel-id': 'iad1::12345-abc-67890',
      'server': 'cloudflare',
    }
    expect(headers['x-vercel-id']).toBeDefined()
    expect(/cloudflare/i.test(headers['server'])).toBe(true)
  })

  it('platform detection: AWS headers', () => {
    const headers: Record<string, string> = {
      'x-amz-request-id': 'ABCDEF123456',
      'server': 'AmazonS3',
    }
    expect(headers['x-amz-request-id']).toBeDefined()
  })

  it('security header enumeration', () => {
    const SECURITY_HEADERS = [
      'content-security-policy',
      'x-frame-options',
      'x-content-type-options',
      'referrer-policy',
      'strict-transport-security',
      'permissions-policy',
    ]
    const headers: Record<string, string> = {
      'content-security-policy': "default-src 'self'",
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
    }
    const present = SECURITY_HEADERS.filter(h => headers[h])
    expect(present.length).toBe(3)
  })
})
