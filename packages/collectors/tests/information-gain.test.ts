import { describe, it, expect } from 'vitest'
import {
  selfInfo,
  registrarInfoGain,
  nameserverInfoGain,
  ipInfoGain,
  cityInfoGain,
  countryInfoGain,
  emailInfoGain,
  trackingIdInfoGain,
  asnInfoGain,
} from '../src/information-gain.js'

describe('selfInfo', () => {
  it('I(1/2) = 1 bit', () => {
    expect(selfInfo(0.5)).toBeCloseTo(1.0, 10)
  })

  it('I(1/1024) = 10 bits', () => {
    expect(selfInfo(1 / 1024)).toBeCloseTo(10.0, 10)
  })

  it('rare events give more bits', () => {
    expect(selfInfo(0.001)).toBeGreaterThan(selfInfo(0.1))
  })

  it('returns 0 for edge cases', () => {
    expect(selfInfo(0)).toBe(0)
    expect(selfInfo(1)).toBe(0)
  })
})

describe('registrarInfoGain', () => {
  it('GoDaddy (14%) ≈ 2.8 bits', () => {
    const bits = registrarInfoGain('GoDaddy.com, LLC')
    expect(bits).toBeGreaterThan(2)
    expect(bits).toBeLessThan(4)
  })

  it('Namecheap (3.2%) ≈ 5.0 bits', () => {
    const bits = registrarInfoGain('NameCheap, Inc.')
    expect(bits).toBeGreaterThan(4)
    expect(bits).toBeLessThan(6)
  })

  it('unknown small registrar > large registrar', () => {
    expect(registrarInfoGain('Obscure Registrar Ltd')).toBeGreaterThan(
      registrarInfoGain('GoDaddy.com, LLC'),
    )
  })

  it('all values > 0', () => {
    expect(registrarInfoGain('GoDaddy')).toBeGreaterThan(0)
    expect(registrarInfoGain('Unknown')).toBeGreaterThan(0)
  })
})

describe('nameserverInfoGain', () => {
  it('Cloudflare NS (20%) ≈ 2.3 bits', () => {
    const bits = nameserverInfoGain(['candy.ns.cloudflare.com', 'yisroel.ns.cloudflare.com'])
    expect(bits).toBeGreaterThan(1.5)
    expect(bits).toBeLessThan(3)
  })

  it('GoDaddy NS (33%) ≈ 1.6 bits', () => {
    const bits = nameserverInfoGain(['ns1.domaincontrol.com', 'ns2.domaincontrol.com'])
    expect(bits).toBeGreaterThan(1)
    expect(bits).toBeLessThan(2.5)
  })

  it('custom NS gives more bits', () => {
    const custom = nameserverInfoGain(['ns1.private-company.com', 'ns2.private-company.com'])
    const cloudflare = nameserverInfoGain(['candy.ns.cloudflare.com'])
    expect(custom).toBeGreaterThan(cloudflare)
  })

  it('custom NS gives ~10 bits', () => {
    const bits = nameserverInfoGain(['ns1.mycompany.internal'])
    expect(bits).toBeGreaterThan(8)
  })
})

describe('ipInfoGain', () => {
  it('CDN IP gives ~1.5 bits', () => {
    const bits = ipInfoGain('104.21.49.223', 13335, true) // Cloudflare ASN
    expect(bits).toBeCloseTo(1.5, 0)
  })

  it('shared hosting gives ~20 bits', () => {
    const bits = ipInfoGain('192.168.1.1', 12345, true) // non-CDN hosting
    expect(bits).toBeGreaterThan(15)
    expect(bits).toBeLessThan(25)
  })

  it('dedicated/residential gives more than shared', () => {
    const dedicated = ipInfoGain('1.2.3.4', null, false)
    const shared = ipInfoGain('1.2.3.4', 12345, true)
    expect(dedicated).toBeGreaterThan(shared)
  })
})

describe('cityInfoGain', () => {
  it('London in UK ≈ 2.9 bits (large city, low gain)', () => {
    const bits = cityInfoGain('London', 'GB')
    expect(bits).toBeGreaterThan(2)
    expect(bits).toBeLessThan(4)
  })

  it('Bradford in UK ≈ 7.0 bits', () => {
    const bits = cityInfoGain('Bradford', 'GB')
    expect(bits).toBeGreaterThan(6)
    expect(bits).toBeLessThan(8)
  })

  it('smaller city gives more bits than larger', () => {
    expect(cityInfoGain('Bradford', 'GB')).toBeGreaterThan(
      cityInfoGain('London', 'GB'),
    )
  })

  it('unknown city uses 100K estimate', () => {
    const bits = cityInfoGain('Smalltown', 'GB')
    // log2(67M / 100K) ≈ 9.4
    expect(bits).toBeGreaterThan(8)
    expect(bits).toBeLessThan(11)
  })
})

describe('countryInfoGain', () => {
  it('UK (67M in 8B) ≈ 6.9 bits', () => {
    expect(countryInfoGain('GB')).toBeCloseTo(6.9, 0)
  })

  it('US (334M in 8B) ≈ 4.6 bits', () => {
    expect(countryInfoGain('US')).toBeCloseTo(4.6, 0)
  })

  it('smaller country gives more bits', () => {
    expect(countryInfoGain('IE')).toBeGreaterThan(countryInfoGain('US'))
  })
})

describe('emailInfoGain', () => {
  it('returns full prior for UK population', () => {
    expect(emailInfoGain(67_000_000)).toBeCloseTo(26.0, 0)
  })

  it('returns full prior for global internet', () => {
    expect(emailInfoGain(5_400_000_000)).toBeCloseTo(32.3, 0)
  })
})

describe('trackingIdInfoGain', () => {
  it('returns near-full prior', () => {
    const bits = trackingIdInfoGain(67_000_000)
    expect(bits).toBeGreaterThan(20)
    expect(bits).toBeLessThan(26)
  })

  it('less than email (could be multi-site)', () => {
    expect(trackingIdInfoGain(67_000_000)).toBeLessThan(emailInfoGain(67_000_000))
  })
})

describe('asnInfoGain', () => {
  it('Cloudflare ASN gives ~2 bits', () => {
    expect(asnInfoGain(13335)).toBeCloseTo(2.0, 0)
  })

  it('small ISP gives more bits', () => {
    expect(asnInfoGain(99999)).toBeGreaterThan(asnInfoGain(13335))
  })

  it('all values > 0', () => {
    expect(asnInfoGain(13335)).toBeGreaterThan(0)
    expect(asnInfoGain(99999)).toBeGreaterThan(0)
  })
})
