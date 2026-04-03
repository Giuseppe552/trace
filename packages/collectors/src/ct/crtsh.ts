/**
 * Certificate Transparency collector via crt.sh.
 *
 * crt.sh is operated by Sectigo. It indexes 14B+ certificates from
 * public CT logs. Free, no registration, no API key.
 *
 * What it reveals:
 * - All certificates ever issued for a domain (including subdomains)
 * - Certificate issuer, validity dates, SANs
 * - Historical infrastructure: staging, dev, internal subdomains
 * - Related domains via shared certificates (SAN field)
 *
 * Attribution value:
 * - Subdomains reveal infrastructure scope
 * - Shared SANs link apparently unrelated domains
 * - Cert issuance dates show when infrastructure was provisioned
 * - Organization field in cert reveals entity behind the domain
 */

import type { CollectorResult, Signal, FetchOptions } from '../types.js'
import { fetchWithTimeout } from '../types.js'
import { CAL } from '../calibration.js'

/** A certificate entry from crt.sh */
export interface CrtShEntry {
  /** crt.sh internal ID */
  id: number
  /** certificate issuer (Let's Encrypt, Cloudflare, etc.) */
  issuerName: string
  /** common name from the certificate */
  commonName: string
  /** all names (SANs) on the certificate */
  nameValue: string
  /** when the cert was logged to CT */
  entryTimestamp: string
  /** cert validity start */
  notBefore: string
  /** cert validity end */
  notAfter: string
  /** serial number */
  serialNumber: string
}

/** Structured result from CT collection */
export interface CtResult {
  /** target domain queried */
  domain: string
  /** all certificate entries found */
  certificates: CrtShEntry[]
  /** unique subdomains discovered */
  subdomains: string[]
  /** unique issuers seen */
  issuers: string[]
  /** domains found via shared SANs (not subdomains of target) */
  relatedDomains: string[]
  /** earliest cert issuance date */
  firstSeen: string | null
  /** most recent cert issuance */
  lastSeen: string | null
}

/**
 * Query crt.sh for all certificates matching a domain.
 *
 * Uses the JSON API: https://crt.sh/?q=%.example.com&output=json
 * The % wildcard matches any subdomain.
 */
export async function collectCT(
  domain: string,
  options: FetchOptions = {},
): Promise<CollectorResult<CtResult>> {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`
  const warnings: string[] = []
  const collectedAt = new Date().toISOString()

  let raw = ''
  let entries: CrtShEntry[] = []

  try {
    const resp = await fetchWithTimeout(url, { ...options, timeout: options.timeout ?? 30_000 })
    raw = await resp.text()

    if (!resp.ok) {
      warnings.push(`crt.sh returned ${resp.status}`)
      return emptyResult(domain, url, raw, collectedAt, warnings)
    }

    const json = JSON.parse(raw) as Array<Record<string, unknown>>

    entries = json.map(row => ({
      id: row.id as number,
      issuerName: (row.issuer_name as string) ?? '',
      commonName: (row.common_name as string) ?? '',
      nameValue: (row.name_value as string) ?? '',
      entryTimestamp: (row.entry_timestamp as string) ?? '',
      notBefore: (row.not_before as string) ?? '',
      notAfter: (row.not_after as string) ?? '',
      serialNumber: (row.serial_number as string) ?? '',
    }))
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    warnings.push(`crt.sh fetch failed: ${msg}`)
    return emptyResult(domain, url, raw, collectedAt, warnings)
  }

  // extract subdomains
  const allNames = new Set<string>()
  for (const entry of entries) {
    for (const name of entry.nameValue.split('\n')) {
      const clean = name.trim().toLowerCase().replace(/^\*\./, '')
      if (clean) allNames.add(clean)
    }
    const cn = entry.commonName.trim().toLowerCase().replace(/^\*\./, '')
    if (cn) allNames.add(cn)
  }

  const domainLower = domain.toLowerCase()
  const subdomains: string[] = []
  const relatedDomains: string[] = []

  for (const name of allNames) {
    if (name === domainLower || name.endsWith(`.${domainLower}`)) {
      if (name !== domainLower) subdomains.push(name)
    } else {
      relatedDomains.push(name)
    }
  }

  // unique issuers
  const issuers = [...new Set(entries.map(e => e.issuerName).filter(Boolean))]

  // date range
  const dates = entries
    .map(e => e.notBefore)
    .filter(Boolean)
    .sort()
  const firstSeen = dates[0] ?? null
  const lastSeen = dates[dates.length - 1] ?? null

  const data: CtResult = {
    domain,
    certificates: entries,
    subdomains: [...new Set(subdomains)].sort(),
    issuers,
    relatedDomains: [...new Set(relatedDomains)].sort(),
    firstSeen,
    lastSeen,
  }

  // build signals
  const signals: Signal[] = []

  if (subdomains.length > 0) {
    signals.push({
      source: 'ct',
      observation: `${subdomains.length} subdomains discovered via CT logs`,
      score: 0.5,
      confidence: 0.9,
      reliability: CAL.CT,
      reliabilityCitation: CAL.CT_CITE,
      informationBits: Math.log2(Math.max(subdomains.length, 1)),
      rawData: subdomains.join(', '),
      sourceUrl: url,
    })
  }

  if (relatedDomains.length > 0) {
    signals.push({
      source: 'ct',
      observation: `${relatedDomains.length} related domains found via shared certificates`,
      score: 0.7,
      confidence: 0.85,
      reliability: CAL.CT,
      reliabilityCitation: CAL.CT_CITE,
      informationBits: Math.log2(Math.max(relatedDomains.length, 1)) + 3,
      rawData: relatedDomains.join(', '),
      sourceUrl: url,
    })
  }

  return { data, signals, raw, url, collectedAt, warnings }
}

function emptyResult(
  domain: string, url: string, raw: string, collectedAt: string, warnings: string[],
): CollectorResult<CtResult> {
  return {
    data: { domain, certificates: [], subdomains: [], issuers: [], relatedDomains: [], firstSeen: null, lastSeen: null },
    signals: [],
    raw,
    url,
    collectedAt,
    warnings,
  }
}
