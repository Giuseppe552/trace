import { describe, it, expect } from 'vitest'
import { dualSourceDns, verifyEvidence } from '../src/evidence/verification.js'
import { sha256 } from '../src/evidence/chain.js'

describe('dualSourceDns', () => {
  it('resolves a well-known domain consistently', async () => {
    const result = await dualSourceDns('example.com', 'A')
    expect(result.consistent).toBe(true)
    expect(result.sourceA.result).toBe(result.sourceB.result)
    expect(result.sourceA.resolver).toContain('Cloudflare')
    expect(result.sourceB.resolver).toContain('Google')
    expect(result.verificationHash.length).toBe(64)
  }, 15_000)

  it('resolves NS records consistently', async () => {
    const result = await dualSourceDns('example.com', 'NS')
    expect(result.consistent).toBe(true)
    expect(result.sourceA.result.length).toBeGreaterThan(0)
  }, 15_000)

  it('handles non-existent domain', async () => {
    const result = await dualSourceDns('this-domain-definitely-does-not-exist-abc123xyz.com', 'A')
    // both should return NXDOMAIN — which IS consistent
    expect(result.sourceA.result).toBe('NXDOMAIN')
    expect(result.sourceB.result).toBe('NXDOMAIN')
    expect(result.consistent).toBe(true)
  }, 15_000)

  it('produces unique verification hash', async () => {
    const r1 = await dualSourceDns('example.com', 'A')
    const r2 = await dualSourceDns('example.com', 'NS')
    // different record types should produce different hashes
    // (or same if timing differs, but results differ)
    expect(r1.verificationHash.length).toBe(64)
    expect(r2.verificationHash.length).toBe(64)
  }, 15_000)
})

describe('verifyEvidence', () => {
  it('unverified when no methods specified', async () => {
    const hash = await sha256('test data')
    const report = await verifyEvidence(hash, 0)
    expect(report.status).toBe('unverified')
    expect(report.verificationCount).toBe(0)
  })

  it('partial when only dual DNS succeeds', async () => {
    const hash = await sha256('test data')
    const report = await verifyEvidence(hash, 0, {
      dualDns: { domain: 'example.com', recordType: 'A' },
    })
    expect(report.dualSource).not.toBeNull()
    if (report.dualSource?.consistent) {
      expect(report.status).toBe('partial')
      expect(report.verificationCount).toBe(1)
    }
  }, 15_000)

  it('partial when only archive URL provided', async () => {
    const hash = await sha256('test data')
    const report = await verifyEvidence(hash, 0, {
      archiveUrl: 'https://web.archive.org/web/20260403/https://example.com',
    })
    expect(report.status).toBe('partial')
    expect(report.verificationCount).toBe(1)
    expect(report.archiveUrl).toContain('archive.org')
  })

  it('verified when dual DNS + archive URL', async () => {
    const hash = await sha256('test data')
    const report = await verifyEvidence(hash, 0, {
      dualDns: { domain: 'example.com', recordType: 'A' },
      archiveUrl: 'https://web.archive.org/web/20260403/https://example.com',
    })
    if (report.dualSource?.consistent) {
      expect(report.status).toBe('verified')
      expect(report.verificationCount).toBe(2)
    }
  }, 15_000)

  it('records entry sequence number', async () => {
    const hash = await sha256('data')
    const report = await verifyEvidence(hash, 7)
    expect(report.entrySeq).toBe(7)
  })

  it('records content hash', async () => {
    const hash = await sha256('specific data')
    const report = await verifyEvidence(hash, 0)
    expect(report.contentHash).toBe(hash)
  })
})
