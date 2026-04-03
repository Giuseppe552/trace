/**
 * RDAP (Registration Data Access Protocol) domain lookup.
 *
 * RDAP is the successor to WHOIS (RFC 9082/9083). Returns structured
 * JSON instead of free text that varies by registrar. Eliminates the
 * ~30% parsing failure rate of raw WHOIS.
 *
 * Query flow:
 * 1. Use rdap.org bootstrap service (redirects to authoritative server)
 * 2. Parse standardized JSON response
 * 3. Extract registrant, registrar, nameservers, dates
 *
 * Falls back to raw WHOIS (TCP port 43) if RDAP is unavailable.
 *
 * Reference: RFC 9082 — RDAP Query Format
 * Reference: RFC 9083 — JSON Responses for RDAP
 * Reference: RFC 7484 — Finding the Authoritative RDAP Service
 */

import type { CollectorResult, Signal, FetchOptions } from '../types.js'
import { fetchWithTimeout } from '../types.js'
import { CAL } from '../calibration.js'
import type { WhoisData } from './lookup.js'
import { collectWhois as collectRawWhois } from './lookup.js'

/** RDAP entity with roles */
interface RdapEntity {
  roles?: string[]
  vcardArray?: [string, Array<[string, Record<string, unknown>, string, string | string[]]>]
  handle?: string
}

/** RDAP nameserver */
interface RdapNameserver {
  ldhName?: string
}

/** RDAP event */
interface RdapEvent {
  eventAction?: string
  eventDate?: string
}

/** Raw RDAP JSON response */
interface RdapResponse {
  objectClassName?: string
  ldhName?: string
  handle?: string
  status?: string[]
  entities?: RdapEntity[]
  nameservers?: RdapNameserver[]
  events?: RdapEvent[]
  links?: Array<{ rel?: string; href?: string }>
  remarks?: Array<{ title?: string; description?: string[] }>
  port43?: string
}

/**
 * Query RDAP via the rdap.org bootstrap service.
 *
 * rdap.org returns a 302 redirect to the authoritative RDAP server
 * for the TLD. We follow the redirect and parse the JSON response.
 */
export async function queryRdap(
  domain: string,
  options: FetchOptions = {},
): Promise<{ data: WhoisData; raw: string; source: 'rdap' | 'whois_fallback' } | null> {
  const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`

  try {
    const resp = await fetchWithTimeout(url, {
      ...options,
      timeout: options.timeout ?? 15_000,
    })

    if (!resp.ok) return null

    const raw = await resp.text()
    const json = JSON.parse(raw) as RdapResponse

    return { data: parseRdap(domain, json), raw, source: 'rdap' }
  } catch {
    return null
  }
}

/**
 * Parse RDAP JSON into the same WhoisData structure used by raw WHOIS.
 * This gives a unified interface regardless of data source.
 */
function parseRdap(domain: string, rdap: RdapResponse): WhoisData {
  // extract registrant from entities
  let registrantName: string | null = null
  let registrantOrg: string | null = null
  let registrantEmail: string | null = null
  let registrantCountry: string | null = null
  let registrar: string | null = null

  for (const entity of rdap.entities ?? []) {
    const roles = entity.roles ?? []

    if (roles.includes('registrant')) {
      const vcard = parseVcard(entity)
      registrantName = vcard.fn
      registrantOrg = vcard.org
      registrantEmail = vcard.email
      registrantCountry = vcard.country
    }

    if (roles.includes('registrar')) {
      const vcard = parseVcard(entity)
      registrar = vcard.fn ?? vcard.org ?? entity.handle ?? null
    }
  }

  // extract dates from events
  let createdDate: string | null = null
  let updatedDate: string | null = null
  let expiresDate: string | null = null

  for (const event of rdap.events ?? []) {
    if (event.eventAction === 'registration') createdDate = event.eventDate ?? null
    if (event.eventAction === 'last changed') updatedDate = event.eventDate ?? null
    if (event.eventAction === 'expiration') expiresDate = event.eventDate ?? null
  }

  // nameservers
  const nameservers = (rdap.nameservers ?? [])
    .map(ns => ns.ldhName?.toLowerCase() ?? '')
    .filter(Boolean)

  // status
  const status = rdap.status ?? []

  // privacy detection — check for redacted markers in remarks or entity names
  const rawStr = JSON.stringify(rdap).toLowerCase()
  const isPrivacyProtected = rawStr.includes('redacted') ||
    rawStr.includes('privacy') ||
    rawStr.includes('withheld') ||
    rawStr.includes('not disclosed')

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
    rawText: JSON.stringify(rdap, null, 2),
  }
}

/**
 * Extract contact info from an RDAP vCard array.
 *
 * vCardArray format: ["vcard", [ [property, params, type, value], ... ]]
 * Example: ["fn", {}, "text", "John Smith"]
 */
function parseVcard(entity: RdapEntity): {
  fn: string | null
  org: string | null
  email: string | null
  country: string | null
} {
  let fn: string | null = null
  let org: string | null = null
  let email: string | null = null
  let country: string | null = null

  if (!entity.vcardArray || entity.vcardArray.length < 2) {
    return { fn, org, email, country }
  }

  const properties = entity.vcardArray[1]
  for (const prop of properties) {
    const [name, , , value] = prop
    if (name === 'fn' && typeof value === 'string') fn = value
    if (name === 'org' && typeof value === 'string') org = value
    if (name === 'email' && typeof value === 'string') email = value
    if (name === 'adr' && Array.isArray(value)) {
      // vCard adr: [pobox, ext, street, locality, region, postal, country]
      country = value[6] ?? null
    }
  }

  return { fn, org, email, country }
}

/**
 * Collect WHOIS data with RDAP as primary source, raw WHOIS as fallback.
 *
 * This is the recommended entry point. It tries RDAP first (structured JSON,
 * no parsing errors) and falls back to raw WHOIS (TCP port 43, regex parsing)
 * only if RDAP fails.
 */
export async function collectWhoisRdap(
  domain: string,
  options: FetchOptions = {},
): Promise<CollectorResult<WhoisData & { dataSource: 'rdap' | 'whois_fallback' }>> {
  const collectedAt = new Date().toISOString()
  const warnings: string[] = []

  // try RDAP first
  const rdapResult = await queryRdap(domain, options)

  if (rdapResult) {
    const data = { ...rdapResult.data, dataSource: 'rdap' as const }
    const signals = buildWhoisSignals(data, `rdap://${domain}`, 'rdap')
    return { data, signals, raw: rdapResult.raw, url: `rdap://${domain}`, collectedAt, warnings }
  }

  // fallback to raw WHOIS
  warnings.push('RDAP unavailable, fell back to raw WHOIS (TCP port 43)')
  const rawResult = await collectRawWhois(domain, options)
  const data = { ...rawResult.data, dataSource: 'whois_fallback' as const }

  return {
    data,
    signals: rawResult.signals,
    raw: rawResult.raw,
    url: rawResult.url,
    collectedAt,
    warnings: [...warnings, ...rawResult.warnings],
  }
}

function buildWhoisSignals(data: WhoisData, url: string, source: string): Signal[] {
  const signals: Signal[] = []

  const REL_VISIBLE = CAL.WHOIS_VISIBLE
  const REL_VISIBLE_CITE = CAL.WHOIS_VISIBLE_CITE
  const REL_REDACTED = CAL.WHOIS_REDACTED
  const REL_REDACTED_CITE = CAL.WHOIS_REDACTED_CITE

  // RDAP parsed data is more reliable than regex-parsed WHOIS
  const sourceNote = source === 'rdap' ? ' (structured RDAP/RFC 9083)' : ' (raw WHOIS, regex-parsed)'

  if (data.registrantEmail && !data.isPrivacyProtected) {
    signals.push({
      source: 'whois',
      observation: `registrant email: ${data.registrantEmail}${sourceNote}`,
      score: 0.9,
      confidence: source === 'rdap' ? 0.98 : 0.92,
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
      observation: `registrant organization: ${data.registrantOrg}${sourceNote}`,
      score: 0.85,
      confidence: source === 'rdap' ? 0.95 : 0.88,
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
      observation: `registrant name: ${data.registrantName}${sourceNote}`,
      score: 0.80,
      confidence: source === 'rdap' ? 0.95 : 0.85,
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
      observation: 'registrant data privacy-protected',
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
      reliability: REL_REDACTED,
      reliabilityCitation: 'NS data is factual but shared across many domains',
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
      reliabilityCitation: 'Registrar data is authoritative from RDAP/WHOIS',
      informationBits: 1.5,
      rawData: data.registrar,
      sourceUrl: url,
    })
  }

  return signals
}
