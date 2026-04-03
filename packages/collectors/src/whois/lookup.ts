/**
 * WHOIS collector for domain attribution.
 *
 * Two modes:
 * 1. Raw WHOIS via TCP (port 43) — free, no API key, but parsing is fragile
 * 2. WhoisFreaks API — structured JSON, freemium (100 free lookups/month)
 *
 * Attribution value:
 * - Registrant name/email/org links domain to a person or company
 * - Registrar + creation date pattern-matches with other domains
 * - Nameservers correlate with other domains (shared infrastructure)
 * - Privacy proxy detection: domains behind the same proxy may share an owner
 *
 * Post-GDPR, most .com/.net registrant data is redacted. Historical WHOIS
 * (from before GDPR) often has the original registrant — use WhoisFreaks
 * history endpoint for that.
 *
 * Reference: DomainTools Cybercrime Investigation Guide (APWG)
 */

import { Socket } from 'node:net'
import type { CollectorResult, Signal } from '../types.js'

/** Structured WHOIS data */
export interface WhoisData {
  domain: string
  registrar: string | null
  createdDate: string | null
  updatedDate: string | null
  expiresDate: string | null
  registrantName: string | null
  registrantOrg: string | null
  registrantEmail: string | null
  registrantCountry: string | null
  nameservers: string[]
  status: string[]
  /** was the registrant data redacted (GDPR proxy)? */
  isPrivacyProtected: boolean
  /** raw WHOIS text */
  rawText: string
}

const WHOIS_SERVERS: Record<string, string> = {
  com: 'whois.verisign-grs.com',
  net: 'whois.verisign-grs.com',
  org: 'whois.pir.org',
  io: 'whois.nic.io',
  co: 'whois.nic.co',
  uk: 'whois.nic.uk',
  'co.uk': 'whois.nic.uk',
  de: 'whois.denic.de',
  nl: 'whois.sidn.nl',
  eu: 'whois.eu',
  us: 'whois.nic.us',
  ca: 'whois.cira.ca',
  au: 'whois.auda.org.au',
}

const PRIVACY_INDICATORS = [
  'redacted for privacy',
  'data protected',
  'whoisguard',
  'withheldforprivacy',
  'contact privacy',
  'domains by proxy',
  'privacy protect',
  'identity protect',
  'not disclosed',
  'statutory masking',
]

/**
 * Raw WHOIS lookup via TCP port 43.
 * Free, no API key. Works for most TLDs.
 */
export async function rawWhoisLookup(
  domain: string,
  options: { timeout?: number } = {},
): Promise<string> {
  const { timeout = 10_000 } = options

  // determine WHOIS server
  const parts = domain.split('.')
  const tld = parts.slice(-2).join('.')
  const topTld = parts[parts.length - 1]
  const server = WHOIS_SERVERS[tld] ?? WHOIS_SERVERS[topTld] ?? `whois.nic.${topTld}`

  return new Promise((resolve, reject) => {
    const socket = new Socket()
    let data = ''

    socket.setTimeout(timeout)
    socket.on('data', (chunk) => { data += chunk.toString() })
    socket.on('end', () => resolve(data))
    socket.on('timeout', () => { socket.destroy(); reject(new Error('WHOIS timeout')) })
    socket.on('error', reject)

    socket.connect(43, server, () => {
      socket.write(`${domain}\r\n`)
    })
  })
}

/**
 * Parse raw WHOIS text into structured data.
 * Fragile — every registrar formats differently.
 */
export function parseWhois(domain: string, raw: string): WhoisData {
  const get = (patterns: string[]): string | null => {
    for (const p of patterns) {
      const re = new RegExp(`${p}:\\s*(.+)`, 'im')
      const match = raw.match(re)
      if (match) return match[1].trim()
    }
    return null
  }

  const registrar = get(['Registrar', 'Sponsoring Registrar'])
  const createdDate = get(['Creation Date', 'Created Date', 'Created', 'Registration Date'])
  const updatedDate = get(['Updated Date', 'Last Updated', 'Last Modified'])
  const expiresDate = get(['Registry Expiry Date', 'Expiration Date', 'Expiry Date'])
  const registrantName = get(['Registrant Name', 'Registrant'])
  const registrantOrg = get(['Registrant Organization', 'Registrant Organisation'])
  const registrantEmail = get(['Registrant Email', 'Registrant Contact Email'])
  const registrantCountry = get(['Registrant Country', 'Registrant Country Code'])

  // nameservers
  const nsMatches = raw.match(/Name Server:\s*(.+)/gi) ?? []
  const nameservers = nsMatches
    .map(m => m.replace(/Name Server:\s*/i, '').trim().toLowerCase())
    .filter(Boolean)

  // status
  const statusMatches = raw.match(/(?:Domain )?Status:\s*(.+)/gi) ?? []
  const status = statusMatches
    .map(m => m.replace(/(?:Domain )?Status:\s*/i, '').trim())
    .filter(Boolean)

  // privacy detection
  const rawLower = raw.toLowerCase()
  const isPrivacyProtected = PRIVACY_INDICATORS.some(indicator =>
    rawLower.includes(indicator),
  )

  return {
    domain,
    registrar,
    createdDate,
    updatedDate,
    expiresDate,
    registrantName,
    registrantOrg,
    registrantEmail,
    registrantCountry,
    nameservers: [...new Set(nameservers)],
    status,
    isPrivacyProtected,
    rawText: raw,
  }
}

/**
 * Full WHOIS collection: lookup + parse + signals.
 */
export async function collectWhois(
  domain: string,
  options: { timeout?: number } = {},
): Promise<CollectorResult<WhoisData>> {
  const collectedAt = new Date().toISOString()
  const warnings: string[] = []
  const url = `whois://${domain}`

  let raw = ''
  try {
    raw = await rawWhoisLookup(domain, options)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    warnings.push(`WHOIS lookup failed: ${msg}`)
  }

  // some registrars return a referral to a different WHOIS server
  const referralMatch = raw.match(/Registrar WHOIS Server:\s*(\S+)/i)
  if (referralMatch && referralMatch[1]) {
    try {
      const referralServer = referralMatch[1]
      const socket = new Socket()
      let referralData = ''

      await new Promise<void>((resolve, reject) => {
        socket.setTimeout(options.timeout ?? 10_000)
        socket.on('data', (chunk) => { referralData += chunk.toString() })
        socket.on('end', () => resolve())
        socket.on('timeout', () => { socket.destroy(); reject(new Error('referral timeout')) })
        socket.on('error', reject)
        socket.connect(43, referralServer, () => {
          socket.write(`${domain}\r\n`)
        })
      })

      if (referralData.length > raw.length) {
        raw = referralData
      }
    } catch {
      warnings.push('referral WHOIS lookup failed')
    }
  }

  const data = parseWhois(domain, raw)

  // build signals
  const signals: Signal[] = []

  // reliability depends on whether registrant data is visible or redacted
  // ICANN ARS Phase 2 Cycle 6 (2018): 92% email operability when visible
  // post-GDPR: 73% of gTLD domains have no registrant email
  const REL_VISIBLE = 0.92
  const REL_VISIBLE_CITE = 'ICANN ARS Phase 2 Cycle 6, 2018: 92% registrant email operability'
  const REL_REDACTED = 0.10
  const REL_REDACTED_CITE = 'WhoisXML API: 73% of gTLD domains have no registrant email post-GDPR'

  if (data.registrantEmail && !data.isPrivacyProtected) {
    signals.push({
      source: 'whois',
      observation: `registrant email: ${data.registrantEmail}`,
      score: 0.9,
      confidence: 0.95,
      reliability: REL_VISIBLE,
      reliabilityCitation: REL_VISIBLE_CITE,
      informationBits: 20.0,
      rawData: data.registrantEmail,
      sourceUrl: url,
    })
  }

  if (data.registrantOrg && !data.isPrivacyProtected) {
    signals.push({
      source: 'whois',
      observation: `registrant organization: ${data.registrantOrg}`,
      score: 0.85,
      confidence: 0.90,
      reliability: REL_VISIBLE,
      reliabilityCitation: REL_VISIBLE_CITE,
      informationBits: 12.0,
      rawData: data.registrantOrg,
      sourceUrl: url,
    })
  }

  if (data.registrantName && !data.isPrivacyProtected) {
    signals.push({
      source: 'whois',
      observation: `registrant name: ${data.registrantName}`,
      score: 0.80,
      confidence: 0.85,
      reliability: REL_VISIBLE,
      reliabilityCitation: REL_VISIBLE_CITE,
      informationBits: 10.0,
      rawData: data.registrantName,
      sourceUrl: url,
    })
  }

  if (data.isPrivacyProtected) {
    signals.push({
      source: 'whois',
      observation: 'registrant data privacy-protected (GDPR redacted)',
      score: 0.1,
      confidence: 0.95,
      reliability: REL_REDACTED,
      reliabilityCitation: REL_REDACTED_CITE,
      informationBits: 0.5,
      rawData: 'privacy-protected',
      sourceUrl: url,
    })
  }

  if (data.nameservers.length > 0) {
    signals.push({
      source: 'whois',
      observation: `nameservers: ${data.nameservers.join(', ')}`,
      score: 0.5,
      confidence: 0.95,
      reliability: REL_REDACTED, // NS data available even when registrant redacted, but low attribution value
      reliabilityCitation: 'NS data is factual but shared across many domains; low attribution specificity',
      informationBits: 2.0,
      rawData: data.nameservers.join(', '),
      sourceUrl: url,
    })
  }

  if (data.registrar) {
    signals.push({
      source: 'whois',
      observation: `registrar: ${data.registrar}`,
      score: 0.3,
      confidence: 0.95,
      reliability: 0.90,
      reliabilityCitation: 'Registrar data is factual from WHOIS; DNS records are factual',
      informationBits: 1.5,
      rawData: data.registrar,
      sourceUrl: url,
    })
  }

  return { data, signals, raw, url, collectedAt, warnings }
}
