/**
 * DNS record collector for infrastructure fingerprinting.
 *
 * Resolves A, AAAA, MX, TXT, NS, CNAME, and SOA records.
 * No external dependencies — uses Node.js dns/promises.
 *
 * Attribution value:
 * - A records reveal hosting provider (IP → ASN → company)
 * - MX records reveal email provider
 * - NS records reveal DNS provider (shared NS = possible shared ownership)
 * - TXT records reveal: SPF (email sending services), site verification
 *   tokens (Google, Bing, Facebook), DMARC policy
 * - SOA records reveal domain admin contact
 */

import { Resolver } from 'node:dns/promises'
import type { CollectorResult, Signal } from '../types.js'
import { CAL } from '../calibration.js'
import { nameserverInfoGain } from '../information-gain.js'

/** Structured DNS result */
export interface DnsResult {
  domain: string
  a: string[]
  aaaa: string[]
  mx: Array<{ priority: number; exchange: string }>
  txt: string[]
  ns: string[]
  cname: string | null
  soa: { nsname: string; hostmaster: string; serial: number } | null
  spf: string | null
  dmarc: string | null
  /** verification tokens found (google-site-verification, etc.) */
  verificationTokens: Array<{ provider: string; token: string }>
}

const VERIFICATION_PATTERNS: Array<{ pattern: RegExp; provider: string }> = [
  { pattern: /^google-site-verification=(.+)$/, provider: 'google' },
  { pattern: /^facebook-domain-verification=(.+)$/, provider: 'facebook' },
  { pattern: /^MS=(.+)$/, provider: 'microsoft' },
  { pattern: /^apple-domain-verification=(.+)$/, provider: 'apple' },
  { pattern: /^_globalsign-domain-verification=(.+)$/, provider: 'globalsign' },
  { pattern: /^atlassian-domain-verification=(.+)$/, provider: 'atlassian' },
  { pattern: /^stripe-verification=(.+)$/, provider: 'stripe' },
  { pattern: /^protonmail-verification=(.+)$/, provider: 'protonmail' },
  { pattern: /^have-i-been-pwned-verification=(.+)$/, provider: 'hibp' },
  { pattern: /^postmark-verification=(.+)$/, provider: 'postmark' },
  { pattern: /^sendinblue-code:(.+)$/, provider: 'brevo' },
  { pattern: /^mailchimp-verification:(.+)$/, provider: 'mailchimp' },
]

/**
 * Collect all DNS records for a domain.
 */
export async function collectDns(
  domain: string,
  options: { timeout?: number } = {},
): Promise<CollectorResult<DnsResult>> {
  const resolver = new Resolver()
  resolver.setServers(['1.1.1.1', '8.8.8.8'])
  const collectedAt = new Date().toISOString()
  const warnings: string[] = []

  const data: DnsResult = {
    domain,
    a: [],
    aaaa: [],
    mx: [],
    txt: [],
    ns: [],
    cname: null,
    soa: null,
    spf: null,
    dmarc: null,
    verificationTokens: [],
  }

  // resolve all record types in parallel
  const results = await Promise.allSettled([
    resolver.resolve4(domain),
    resolver.resolve6(domain),
    resolver.resolveMx(domain),
    resolver.resolveTxt(domain),
    resolver.resolveNs(domain),
    resolver.resolveCname(domain),
    resolver.resolveSoa(domain),
    resolver.resolveTxt(`_dmarc.${domain}`),
  ])

  // A records
  if (results[0].status === 'fulfilled') {
    data.a = results[0].value
  }

  // AAAA records
  if (results[1].status === 'fulfilled') {
    data.aaaa = results[1].value
  }

  // MX records
  if (results[2].status === 'fulfilled') {
    data.mx = results[2].value.sort((a, b) => a.priority - b.priority)
  }

  // TXT records
  if (results[3].status === 'fulfilled') {
    data.txt = results[3].value.map(chunks => chunks.join(''))

    // extract SPF
    data.spf = data.txt.find(t => t.startsWith('v=spf1')) ?? null

    // extract verification tokens
    for (const txt of data.txt) {
      for (const { pattern, provider } of VERIFICATION_PATTERNS) {
        const match = txt.match(pattern)
        if (match) {
          data.verificationTokens.push({ provider, token: match[1] })
        }
      }
    }
  }

  // NS records
  if (results[4].status === 'fulfilled') {
    data.ns = results[4].value.sort()
  }

  // CNAME
  if (results[5].status === 'fulfilled') {
    data.cname = results[5].value[0] ?? null
  }

  // SOA
  if (results[6].status === 'fulfilled') {
    const soa = results[6].value
    data.soa = { nsname: soa.nsname, hostmaster: soa.hostmaster, serial: soa.serial }
  }

  // DMARC
  if (results[7].status === 'fulfilled') {
    const dmarcTxts = results[7].value.map(chunks => chunks.join(''))
    data.dmarc = dmarcTxts.find(t => t.startsWith('v=DMARC1')) ?? null
  }

  // build raw representation
  const raw = JSON.stringify(data, null, 2)
  const url = `dns://${domain}`

  // build signals
  const signals: Signal[] = []

  if (data.ns.length > 0) {
    signals.push({
      source: 'dns',
      observation: `nameservers: ${data.ns.join(', ')}`,
      score: 0.5,
      confidence: 0.9,
      reliability: CAL.DNS,
      reliabilityCitation: CAL.DNS_CITE,
      informationBits: nameserverInfoGain(data.ns),
      rawData: data.ns.join(', '),
      sourceUrl: url,
    })
  }

  if (data.mx.length > 0) {
    const primary = data.mx[0].exchange
    signals.push({
      source: 'dns',
      observation: `email provider: ${primary}`,
      score: 0.4,
      confidence: 0.9,
      reliability: CAL.DNS,
      reliabilityCitation: CAL.DNS_CITE,
      informationBits: 1.5,
      rawData: data.mx.map(m => `${m.priority} ${m.exchange}`).join(', '),
      sourceUrl: url,
    })
  }

  if (data.verificationTokens.length > 0) {
    signals.push({
      source: 'dns',
      observation: `verified with: ${data.verificationTokens.map(t => t.provider).join(', ')}`,
      score: 0.6,
      confidence: 0.95,
      reliability: CAL.TRACKING_GA, // verification tokens are near-unique like tracking IDs
      reliabilityCitation: CAL.TRACKING_GA_CITE,
      informationBits: data.verificationTokens.length * 1.5,
      rawData: JSON.stringify(data.verificationTokens),
      sourceUrl: url,
    })
  }

  if (data.a.length > 0) {
    signals.push({
      source: 'dns',
      observation: `hosted on: ${data.a.join(', ')}`,
      score: 0.4,
      confidence: 0.95,
      reliability: CAL.DNS,
      reliabilityCitation: CAL.DNS_CITE,
      informationBits: 1.0,
      rawData: data.a.join(', '),
      sourceUrl: url,
    })
  }

  if (data.soa?.hostmaster) {
    const email = data.soa.hostmaster.replace(/\./, '@', )
    signals.push({
      source: 'dns',
      observation: `SOA hostmaster: ${email}`,
      score: 0.5,
      confidence: 0.7,
      reliability: CAL.DNS,
      reliabilityCitation: CAL.DNS_CITE,
      informationBits: 3.0,
      rawData: data.soa.hostmaster,
      sourceUrl: url,
    })
  }

  return { data, signals, raw, url, collectedAt, warnings }
}
