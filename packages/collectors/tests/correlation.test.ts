import { describe, it, expect } from 'vitest'
import { correlateDomains, type DomainSignals } from '../src/correlation/cross-domain.js'

const DOMAIN_A: DomainSignals = {
  domain: 'competitor-agency.co.uk',
  ips: ['104.21.49.223', '172.67.152.253'],
  nameservers: ['candy.ns.cloudflare.com', 'yisroel.ns.cloudflare.com'],
  mxRecords: ['mx1.privateemail.com', 'mx2.privateemail.com'],
  registrant: 'John Smith',
  registrar: 'Namecheap, Inc.',
  trackingIds: [{ type: 'google-analytics-ga4', value: 'G-ABC1234567' }],
  platform: 'vercel+cloudflare',
  subdomains: ['www.competitor-agency.co.uk'],
  relatedDomains: [],
  verificationTokens: [{ provider: 'google', token: 'xyz123' }],
}

const DOMAIN_B: DomainSignals = {
  domain: 'fake-review-site.com',
  ips: ['104.21.49.223'], // same IP as domain A
  nameservers: ['candy.ns.cloudflare.com', 'yisroel.ns.cloudflare.com'], // same NS
  mxRecords: ['mx1.privateemail.com', 'mx2.privateemail.com'], // same email
  registrant: 'John Smith', // same registrant
  registrar: 'Namecheap, Inc.',
  trackingIds: [{ type: 'google-analytics-ga4', value: 'G-ABC1234567' }], // same GA!
  platform: 'vercel+cloudflare',
  subdomains: [],
  relatedDomains: [],
  verificationTokens: [{ provider: 'google', token: 'xyz123' }], // same verification
}

const DOMAIN_C: DomainSignals = {
  domain: 'unrelated-site.org',
  ips: ['93.184.216.34'],
  nameservers: ['ns1.example.org', 'ns2.example.org'],
  mxRecords: ['mail.example.org'],
  registrant: null,
  registrar: 'GoDaddy',
  trackingIds: [],
  platform: 'nginx',
  subdomains: [],
  relatedDomains: [],
  verificationTokens: [],
}

describe('correlateDomains', () => {
  it('finds shared IP addresses', () => {
    const result = correlateDomains([DOMAIN_A, DOMAIN_B])
    const ipCorrelation = result.correlations.find(c => c.attribute === 'ip_address')
    expect(ipCorrelation).toBeDefined()
    expect(ipCorrelation!.domains).toContain('competitor-agency.co.uk')
    expect(ipCorrelation!.domains).toContain('fake-review-site.com')
    expect(ipCorrelation!.strength).toBe('definitive')
  })

  it('finds shared tracking IDs', () => {
    const result = correlateDomains([DOMAIN_A, DOMAIN_B])
    const gaCorrelation = result.correlations.find(c => c.attribute === 'tracking_id')
    expect(gaCorrelation).toBeDefined()
    expect(gaCorrelation!.value).toContain('G-ABC1234567')
    expect(gaCorrelation!.strength).toBe('definitive')
  })

  it('finds shared registrant', () => {
    const result = correlateDomains([DOMAIN_A, DOMAIN_B])
    const regCorrelation = result.correlations.find(c => c.attribute === 'registrant')
    expect(regCorrelation).toBeDefined()
    expect(regCorrelation!.value).toContain('john smith')
  })

  it('finds shared verification tokens', () => {
    const result = correlateDomains([DOMAIN_A, DOMAIN_B])
    const tokenCorrelation = result.correlations.find(c => c.attribute === 'verification_token')
    expect(tokenCorrelation).toBeDefined()
  })

  it('finds shared nameservers', () => {
    const result = correlateDomains([DOMAIN_A, DOMAIN_B])
    const nsCorrelation = result.correlations.find(c => c.attribute === 'nameserver')
    expect(nsCorrelation).toBeDefined()
  })

  it('no false correlations with unrelated domain', () => {
    const result = correlateDomains([DOMAIN_A, DOMAIN_C])
    const definitive = result.correlations.filter(c => c.strength === 'definitive')
    expect(definitive.length).toBe(0)
  })

  it('generates attribution signals from non-weak correlations', () => {
    const result = correlateDomains([DOMAIN_A, DOMAIN_B])
    expect(result.signals.length).toBeGreaterThan(0)
    // all signals should have score > 0
    for (const s of result.signals) {
      expect(s.score).toBeGreaterThan(0)
    }
  })

  it('builds clusters of related domains', () => {
    const result = correlateDomains([DOMAIN_A, DOMAIN_B, DOMAIN_C])
    // A and B should be in one cluster, C alone (or not in any cluster)
    const abCluster = result.clusterSizes.find(c =>
      c.domains.includes('competitor-agency.co.uk') && c.domains.includes('fake-review-site.com'),
    )
    expect(abCluster).toBeDefined()
    expect(abCluster!.sharedAttributes.length).toBeGreaterThan(2)
  })

  it('unrelated domain not in any cluster', () => {
    const result = correlateDomains([DOMAIN_A, DOMAIN_B, DOMAIN_C])
    const cCluster = result.clusterSizes.find(c =>
      c.domains.includes('unrelated-site.org'),
    )
    expect(cCluster).toBeUndefined()
  })

  it('handles single domain input', () => {
    const result = correlateDomains([DOMAIN_A])
    expect(result.correlations.length).toBe(0)
    expect(result.clusterSizes.length).toBe(0)
  })

  it('handles empty input', () => {
    const result = correlateDomains([])
    expect(result.correlations.length).toBe(0)
    expect(result.signals.length).toBe(0)
  })

  it('correlation information bits > 0', () => {
    const result = correlateDomains([DOMAIN_A, DOMAIN_B])
    for (const c of result.correlations) {
      expect(c.informationBits).toBeGreaterThan(0)
    }
  })

  it('all domains accounted for', () => {
    const result = correlateDomains([DOMAIN_A, DOMAIN_B, DOMAIN_C])
    expect(result.domains.length).toBe(3)
  })
})
