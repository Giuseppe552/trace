import { describe, it, expect } from 'vitest'
import {
  sha256,
  createChain,
  appendEvidence,
  verifyChain,
  exportReport,
} from '../src/evidence/chain.js'

describe('sha256', () => {
  it('produces 64-char hex string', async () => {
    const hash = await sha256('hello')
    expect(hash.length).toBe(64)
    expect(/^[0-9a-f]+$/.test(hash)).toBe(true)
  })

  it('deterministic', async () => {
    const a = await sha256('test input')
    const b = await sha256('test input')
    expect(a).toBe(b)
  })

  it('different inputs produce different hashes', async () => {
    const a = await sha256('input a')
    const b = await sha256('input b')
    expect(a).not.toBe(b)
  })

  it('known vector: empty string', async () => {
    const hash = await sha256('')
    expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  })
})

describe('evidence chain', () => {
  it('creates empty chain', () => {
    const chain = createChain('INV-001', 'giuseppe')
    expect(chain.entries.length).toBe(0)
    expect(chain.investigationId).toBe('INV-001')
    expect(chain.analyst).toBe('giuseppe')
  })

  it('appends entry with correct seq', async () => {
    const chain = createChain('INV-002', 'giuseppe')
    const e1 = await appendEvidence(chain, {
      content: 'WHOIS record for example.com',
      type: 'whois_record',
      source: 'whoisfreaks.com/api/v1/whois?domainName=example.com',
      description: 'WHOIS lookup for target domain',
      layer: 'whois',
    })
    expect(e1.seq).toBe(0)
    expect(chain.entries.length).toBe(1)

    const e2 = await appendEvidence(chain, {
      content: 'DNS TXT records',
      type: 'dns_record',
      source: 'dig +short example.com TXT',
      description: 'DNS TXT records for SPF/DMARC check',
      layer: 'dns',
    })
    expect(e2.seq).toBe(1)
    expect(chain.entries.length).toBe(2)
  })

  it('genesis entry has all-zero prevHash', async () => {
    const chain = createChain('INV-003', 'giuseppe')
    await appendEvidence(chain, {
      content: 'test',
      type: 'other',
      source: 'test',
      description: 'test entry',
      layer: 'test',
    })
    expect(chain.entries[0].prevHash).toBe('0'.repeat(64))
  })

  it('subsequent entries chain to previous', async () => {
    const chain = createChain('INV-004', 'giuseppe')
    const e1 = await appendEvidence(chain, {
      content: 'first',
      type: 'other',
      source: 'test',
      description: 'first entry',
      layer: 'test',
    })
    const e2 = await appendEvidence(chain, {
      content: 'second',
      type: 'other',
      source: 'test',
      description: 'second entry',
      layer: 'test',
    })
    expect(e2.prevHash).toBe(e1.entryHash)
  })

  it('contentHash differs for different content', async () => {
    const chain = createChain('INV-005', 'giuseppe')
    const e1 = await appendEvidence(chain, {
      content: 'content A',
      type: 'other',
      source: 'test',
      description: 'a',
      layer: 'test',
    })
    const e2 = await appendEvidence(chain, {
      content: 'content B',
      type: 'other',
      source: 'test',
      description: 'b',
      layer: 'test',
    })
    expect(e1.contentHash).not.toBe(e2.contentHash)
  })

  it('entryHash is unique per entry', async () => {
    const chain = createChain('INV-006', 'giuseppe')
    await appendEvidence(chain, { content: 'a', type: 'other', source: 's', description: 'd', layer: 'l' })
    await appendEvidence(chain, { content: 'b', type: 'other', source: 's', description: 'd', layer: 'l' })
    await appendEvidence(chain, { content: 'c', type: 'other', source: 's', description: 'd', layer: 'l' })

    const hashes = chain.entries.map(e => e.entryHash)
    expect(new Set(hashes).size).toBe(3)
  })
})

describe('verifyChain', () => {
  it('valid chain passes verification', async () => {
    const chain = createChain('INV-007', 'giuseppe')
    await appendEvidence(chain, { content: 'whois data', type: 'whois_record', source: 'api', description: 'domain lookup', layer: 'whois' })
    await appendEvidence(chain, { content: 'cert data', type: 'certificate', source: 'crt.sh', description: 'CT log entry', layer: 'ct' })
    await appendEvidence(chain, { content: 'dns data', type: 'dns_record', source: 'dig', description: 'DNS records', layer: 'dns' })

    const result = await verifyChain(chain)
    expect(result.intact).toBe(true)
    expect(result.brokenAt).toBe(-1)
    expect(result.totalEntries).toBe(3)
  })

  it('tampered contentHash detected', async () => {
    const chain = createChain('INV-008', 'giuseppe')
    await appendEvidence(chain, { content: 'original', type: 'other', source: 's', description: 'd', layer: 'l' })
    await appendEvidence(chain, { content: 'also original', type: 'other', source: 's', description: 'd', layer: 'l' })

    // tamper with entry 1
    chain.entries[1].contentHash = 'aaaa' + chain.entries[1].contentHash.slice(4)

    const result = await verifyChain(chain)
    expect(result.intact).toBe(false)
    expect(result.brokenAt).toBe(1)
  })

  it('tampered prevHash detected', async () => {
    const chain = createChain('INV-009', 'giuseppe')
    await appendEvidence(chain, { content: 'a', type: 'other', source: 's', description: 'd', layer: 'l' })
    await appendEvidence(chain, { content: 'b', type: 'other', source: 's', description: 'd', layer: 'l' })

    chain.entries[1].prevHash = 'bbbb' + chain.entries[1].prevHash.slice(4)

    const result = await verifyChain(chain)
    expect(result.intact).toBe(false)
    expect(result.brokenAt).toBe(1)
  })

  it('swapped entries detected', async () => {
    const chain = createChain('INV-010', 'giuseppe')
    await appendEvidence(chain, { content: 'first', type: 'other', source: 's', description: 'd', layer: 'l' })
    await appendEvidence(chain, { content: 'second', type: 'other', source: 's', description: 'd', layer: 'l' })
    await appendEvidence(chain, { content: 'third', type: 'other', source: 's', description: 'd', layer: 'l' })

    // swap entries 1 and 2
    const tmp = chain.entries[1]
    chain.entries[1] = chain.entries[2]
    chain.entries[2] = tmp

    const result = await verifyChain(chain)
    expect(result.intact).toBe(false)
  })

  it('empty chain is valid', async () => {
    const chain = createChain('INV-011', 'giuseppe')
    const result = await verifyChain(chain)
    expect(result.intact).toBe(true)
    expect(result.totalEntries).toBe(0)
  })

  it('single entry chain is valid', async () => {
    const chain = createChain('INV-012', 'giuseppe')
    await appendEvidence(chain, { content: 'only entry', type: 'other', source: 's', description: 'd', layer: 'l' })
    const result = await verifyChain(chain)
    expect(result.intact).toBe(true)
  })
})

describe('exportReport', () => {
  it('produces valid JSON', async () => {
    const chain = createChain('INV-013', 'giuseppe')
    await appendEvidence(chain, { content: 'data', type: 'whois_record', source: 'api', description: 'test', layer: 'whois' })
    const report = exportReport(chain)
    const parsed = JSON.parse(report)
    expect(parsed._format).toBe('trace-evidence-chain-v1')
    expect(parsed._protocol).toContain('Berkeley Protocol')
    expect(parsed.totalEntries).toBe(1)
  })

  it('includes all entries', async () => {
    const chain = createChain('INV-014', 'giuseppe')
    for (let i = 0; i < 5; i++) {
      await appendEvidence(chain, { content: `entry ${i}`, type: 'other', source: 's', description: `entry ${i}`, layer: 'l' })
    }
    const parsed = JSON.parse(exportReport(chain))
    expect(parsed.entries.length).toBe(5)
  })
})
