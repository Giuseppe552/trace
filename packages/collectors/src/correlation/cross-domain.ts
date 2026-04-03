/**
 * Cross-domain correlation engine.
 *
 * Given multiple domains, compares signals across them to find shared
 * infrastructure, shared operators, or coordinated activity.
 *
 * This is where trace gets powerful: a single domain investigation
 * gives partial signals. Cross-referencing multiple domains reveals
 * patterns that are invisible in isolation.
 *
 * Correlation signals:
 * - Shared IP addresses → same hosting account
 * - Shared nameservers → same DNS provider/account
 * - Shared registrant (WHOIS) → same owner
 * - Shared tracking IDs (GA, GTM) → same analytics account (very strong)
 * - Shared SSL certificate (SANs) → provisioned together
 * - Shared MX records → same email infrastructure
 * - Overlapping CT subdomains → related infrastructure
 */

import type { Signal } from '../types.js'

/** Signals from a single domain investigation */
export interface DomainSignals {
  domain: string
  ips: string[]
  nameservers: string[]
  mxRecords: string[]
  registrant: string | null
  registrar: string | null
  trackingIds: Array<{ type: string; value: string }>
  platform: string | null
  subdomains: string[]
  relatedDomains: string[]
  verificationTokens: Array<{ provider: string; token: string }>
}

/** A correlation finding between domains */
export interface Correlation {
  /** which domains share this attribute */
  domains: string[]
  /** what's shared */
  attribute: string
  /** the shared value */
  value: string
  /** how strong is this correlation? */
  strength: 'definitive' | 'strong' | 'moderate' | 'weak'
  /** information gain in bits */
  informationBits: number
}

/** Full correlation result */
export interface CorrelationResult {
  /** domains analyzed */
  domains: string[]
  /** all correlations found */
  correlations: Correlation[]
  /** attribution signals from correlations */
  signals: Signal[]
  /** summary: how many domains appear to share an operator */
  clusterSizes: Array<{ domains: string[]; sharedAttributes: string[] }>
}

/**
 * Find correlations across multiple domain signal sets.
 */
export function correlateDomains(domainSignals: DomainSignals[]): CorrelationResult {
  const correlations: Correlation[] = []
  const domains = domainSignals.map(d => d.domain)

  // shared IPs
  findShared(
    domainSignals,
    d => d.ips,
    'ip_address',
    'definitive',
    15.0,
    correlations,
  )

  // shared nameservers
  findShared(
    domainSignals,
    d => d.nameservers,
    'nameserver',
    'moderate',
    3.0,
    correlations,
  )

  // shared MX records
  findShared(
    domainSignals,
    d => d.mxRecords,
    'mx_record',
    'moderate',
    4.0,
    correlations,
  )

  // shared tracking IDs (very strong — links to specific account)
  const trackingMap = new Map<string, string[]>()
  for (const ds of domainSignals) {
    for (const tid of ds.trackingIds) {
      const key = `${tid.type}:${tid.value}`
      const list = trackingMap.get(key) ?? []
      list.push(ds.domain)
      trackingMap.set(key, list)
    }
  }
  for (const [key, doms] of trackingMap) {
    if (doms.length > 1) {
      correlations.push({
        domains: doms,
        attribute: 'tracking_id',
        value: key,
        strength: 'definitive',
        informationBits: 20.0, // tracking ID is near-unique
      })
    }
  }

  // shared registrant
  const registrantMap = new Map<string, string[]>()
  for (const ds of domainSignals) {
    if (ds.registrant) {
      const key = ds.registrant.toLowerCase().trim()
      const list = registrantMap.get(key) ?? []
      list.push(ds.domain)
      registrantMap.set(key, list)
    }
  }
  for (const [registrant, doms] of registrantMap) {
    if (doms.length > 1) {
      correlations.push({
        domains: doms,
        attribute: 'registrant',
        value: registrant,
        strength: 'definitive',
        informationBits: 18.0,
      })
    }
  }

  // shared registrar (weak — many domains use the same registrar)
  findSharedScalar(
    domainSignals,
    d => d.registrar,
    'registrar',
    'weak',
    1.0,
    correlations,
  )

  // shared platform
  findSharedScalar(
    domainSignals,
    d => d.platform,
    'platform',
    'weak',
    0.5,
    correlations,
  )

  // shared verification tokens (strong — links to same third-party account)
  const tokenMap = new Map<string, string[]>()
  for (const ds of domainSignals) {
    for (const token of ds.verificationTokens) {
      const key = `${token.provider}:${token.token}`
      const list = tokenMap.get(key) ?? []
      list.push(ds.domain)
      tokenMap.set(key, list)
    }
  }
  for (const [key, doms] of tokenMap) {
    if (doms.length > 1) {
      correlations.push({
        domains: doms,
        attribute: 'verification_token',
        value: key,
        strength: 'definitive',
        informationBits: 18.0,
      })
    }
  }

  // related domains found in CT logs that match other investigated domains
  for (const ds of domainSignals) {
    for (const related of ds.relatedDomains) {
      const matchingDomain = domainSignals.find(other =>
        other.domain !== ds.domain && (
          other.domain === related ||
          related.endsWith(`.${other.domain}`)
        ),
      )
      if (matchingDomain) {
        correlations.push({
          domains: [ds.domain, matchingDomain.domain],
          attribute: 'shared_certificate',
          value: `${ds.domain} certificate includes ${related}`,
          strength: 'strong',
          informationBits: 10.0,
        })
      }
    }
  }

  // build signals from correlations
  const signals: Signal[] = correlations
    .filter(c => c.strength !== 'weak')
    .map(c => ({
      source: 'correlation',
      observation: `${c.domains.join(' + ')} share ${c.attribute}: ${c.value}`,
      score: c.strength === 'definitive' ? 0.95 : c.strength === 'strong' ? 0.80 : 0.50,
      confidence: c.strength === 'definitive' ? 0.95 : c.strength === 'strong' ? 0.85 : 0.65,
      informationBits: c.informationBits,
      rawData: JSON.stringify(c),
      sourceUrl: 'cross-domain-correlation',
    }))

  // cluster domains by shared attributes
  const clusterSizes = buildClusters(correlations, domains)

  return { domains, correlations, signals, clusterSizes }
}

function findShared(
  domainSignals: DomainSignals[],
  extract: (d: DomainSignals) => string[],
  attribute: string,
  strength: Correlation['strength'],
  bits: number,
  out: Correlation[],
) {
  const valueMap = new Map<string, string[]>()
  for (const ds of domainSignals) {
    for (const val of extract(ds)) {
      const key = val.toLowerCase().trim()
      const list = valueMap.get(key) ?? []
      list.push(ds.domain)
      valueMap.set(key, list)
    }
  }
  for (const [value, doms] of valueMap) {
    if (doms.length > 1) {
      out.push({ domains: [...new Set(doms)], attribute, value, strength, informationBits: bits })
    }
  }
}

function findSharedScalar(
  domainSignals: DomainSignals[],
  extract: (d: DomainSignals) => string | null,
  attribute: string,
  strength: Correlation['strength'],
  bits: number,
  out: Correlation[],
) {
  const valueMap = new Map<string, string[]>()
  for (const ds of domainSignals) {
    const val = extract(ds)
    if (val) {
      const key = val.toLowerCase().trim()
      const list = valueMap.get(key) ?? []
      list.push(ds.domain)
      valueMap.set(key, list)
    }
  }
  for (const [value, doms] of valueMap) {
    if (doms.length > 1) {
      out.push({ domains: [...new Set(doms)], attribute, value, strength, informationBits: bits })
    }
  }
}

function buildClusters(
  correlations: Correlation[],
  allDomains: string[],
): Array<{ domains: string[]; sharedAttributes: string[] }> {
  // union-find to group domains connected by non-weak correlations
  const parent = new Map<string, string>()
  for (const d of allDomains) parent.set(d, d)

  function find(x: string): string {
    while (parent.get(x) !== x) {
      parent.set(x, parent.get(parent.get(x)!)!)
      x = parent.get(x)!
    }
    return x
  }

  function union(a: string, b: string) {
    const ra = find(a), rb = find(b)
    if (ra !== rb) parent.set(ra, rb)
  }

  for (const c of correlations) {
    if (c.strength === 'weak') continue
    for (let i = 1; i < c.domains.length; i++) {
      union(c.domains[0], c.domains[i])
    }
  }

  // group by root
  const groups = new Map<string, { domains: Set<string>; attrs: Set<string> }>()
  for (const d of allDomains) {
    const root = find(d)
    if (!groups.has(root)) groups.set(root, { domains: new Set(), attrs: new Set() })
    groups.get(root)!.domains.add(d)
  }

  for (const c of correlations) {
    if (c.strength === 'weak') continue
    const root = find(c.domains[0])
    groups.get(root)?.attrs.add(c.attribute)
  }

  return [...groups.values()]
    .filter(g => g.domains.size > 1)
    .map(g => ({ domains: [...g.domains], sharedAttributes: [...g.attrs] }))
}
