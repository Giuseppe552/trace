import { describe, it, expect } from 'vitest'
import { analyzeBacklinks } from '../src/brand/backlinks.js'

const CLEAN_DOMAINS = [
  'bbc.co.uk',
  'theguardian.com',
  'techcrunch.com',
  'vercel.com',
  'github.com',
]

const SPAMMY_DOMAINS = [
  'cheap-viagra-buy-now-online.xyz',
  'best-casino-slots-free-2026.top',
  'abcdefghijklmnopqrst.tk',
  'buy-cheap-seo-links-fast.gq',
  'free-traffic-boost-click-here.ml',
  'get-discount-deals-now-today.cf',
  'mega-slot-poker-bet-win.wang',
  '12345678901234.ga',
  'best--seo--links--cheap.bid',
  'adult-content-free-xxx-site.win',
]

describe('analyzeBacklinks', () => {
  it('clean domains have low toxicity', async () => {
    const result = await analyzeBacklinks('target.com', CLEAN_DOMAINS, { checkDns: false })
    expect(result.toxicityScore).toBeLessThan(0.2)
    expect(result.likelyNegativeSeo).toBe(false)
  })

  it('spammy domains have high toxicity', async () => {
    const result = await analyzeBacklinks('target.com', SPAMMY_DOMAINS, { checkDns: false })
    expect(result.toxicityScore).toBeGreaterThan(0.3)
    expect(result.spamCount).toBeGreaterThan(5)
  })

  it('detects negative SEO when >30% spammy', async () => {
    const mixed = [...CLEAN_DOMAINS, ...SPAMMY_DOMAINS]
    const result = await analyzeBacklinks('target.com', mixed, { checkDns: false })
    // 10 spammy out of 15 = 66% > 30% threshold
    expect(result.likelyNegativeSeo).toBe(true)
  })

  it('detects spam keyword domains', async () => {
    const result = await analyzeBacklinks('target.com', ['best-casino-free.com'], { checkDns: false })
    const domain = result.referringDomains[0]
    expect(domain.spamReasons).toContain('spam keyword in domain')
  })

  it('detects spam TLDs', async () => {
    const result = await analyzeBacklinks('target.com', ['random.xyz'], { checkDns: false })
    const domain = result.referringDomains[0]
    expect(domain.spamReasons).toContain('spam-associated TLD')
  })

  it('generates signals for spam', async () => {
    const result = await analyzeBacklinks('target.com', SPAMMY_DOMAINS, { checkDns: false })
    expect(result.signals.length).toBeGreaterThan(0)
  })

  it('handles empty input', async () => {
    const result = await analyzeBacklinks('target.com', [], { checkDns: false })
    expect(result.referringDomains.length).toBe(0)
    expect(result.toxicityScore).toBe(0)
  })

  it('toxicityScore ∈ [0, 1]', async () => {
    const result = await analyzeBacklinks('target.com', SPAMMY_DOMAINS, { checkDns: false })
    expect(result.toxicityScore).toBeGreaterThanOrEqual(0)
    expect(result.toxicityScore).toBeLessThanOrEqual(1)
  })

  it('spamScore per domain ∈ [0, 1]', async () => {
    const result = await analyzeBacklinks('target.com', [...CLEAN_DOMAINS, ...SPAMMY_DOMAINS], { checkDns: false })
    for (const d of result.referringDomains) {
      expect(d.spamScore).toBeGreaterThanOrEqual(0)
      expect(d.spamScore).toBeLessThanOrEqual(1)
    }
  })
})
