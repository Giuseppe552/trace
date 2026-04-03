/**
 * Historical WHOIS lookup.
 *
 * Retrieves past WHOIS records for a domain — snapshots from before
 * GDPR redaction. Many domains registered pre-2018 have historical
 * records with full registrant details that are now redacted.
 *
 * Uses WhoisFreaks historical API (freemium).
 *
 * Attribution value:
 * - Pre-GDPR records may contain unredacted registrant email/name/org
 * - Registration history shows ownership changes
 * - Nameserver changes reveal infrastructure migrations
 * - Creation date consistency across related domains
 */

import type { CollectorResult, Signal, FetchOptions } from '../types.js'
import { fetchWithTimeout } from '../types.js'

/** A historical WHOIS snapshot */
export interface WhoisSnapshot {
  /** when this snapshot was captured */
  snapshotDate: string
  registrantName: string | null
  registrantOrg: string | null
  registrantEmail: string | null
  registrantCountry: string | null
  registrar: string | null
  nameservers: string[]
  createdDate: string | null
  updatedDate: string | null
  expiresDate: string | null
  isPrivacyProtected: boolean
}

/** Historical WHOIS result */
export interface WhoisHistoryResult {
  domain: string
  snapshots: WhoisSnapshot[]
  /** earliest snapshot date */
  oldestRecord: string | null
  /** was the registrant ever visible (pre-GDPR)? */
  hasUnredactedRecords: boolean
  /** distinct registrant identities found across history */
  distinctRegistrants: Array<{ name: string | null; email: string | null; org: string | null; firstSeen: string }>
}

const PRIVACY_INDICATORS = [
  'redacted', 'privacy', 'whoisguard', 'withheld', 'not disclosed',
  'data protected', 'domains by proxy', 'contact privacy',
]

/**
 * Fetch historical WHOIS via WhoisFreaks API.
 *
 * Requires API key. Free tier supports historical queries.
 */
export async function whoisHistory(
  domain: string,
  options: FetchOptions & { apiKey?: string } = {},
): Promise<CollectorResult<WhoisHistoryResult>> {
  const apiKey = options.apiKey ?? process.env.WHOISFREAKS_API_KEY
  const collectedAt = new Date().toISOString()
  const warnings: string[] = []

  const data: WhoisHistoryResult = {
    domain,
    snapshots: [],
    oldestRecord: null,
    hasUnredactedRecords: false,
    distinctRegistrants: [],
  }

  if (!apiKey) {
    warnings.push('WHOISFREAKS_API_KEY not set — historical WHOIS unavailable')
    return { data, signals: [], raw: '', url: '', collectedAt, warnings }
  }

  const url = `https://api.whoisfreaks.com/v1.0/whois?apiKey=${apiKey}&whois=historical&domainName=${encodeURIComponent(domain)}`
  let raw = ''

  try {
    const resp = await fetchWithTimeout(url, { ...options, timeout: options.timeout ?? 20_000 })
    raw = await resp.text()

    if (!resp.ok) {
      warnings.push(`WhoisFreaks returned ${resp.status}`)
      return { data, signals: [], raw, url: url.replace(apiKey, 'REDACTED'), collectedAt, warnings }
    }

    const json = JSON.parse(raw) as {
      whois_records?: Array<{
        query_time?: string
        registrant_contact?: {
          name?: string
          company?: string
          email?: string
          country_code?: string
        }
        domain_registrar?: { registrar_name?: string }
        name_servers?: string[]
        create_date?: string
        update_date?: string
        expiry_date?: string
      }>
    }

    for (const rec of json.whois_records ?? []) {
      const registrantName = rec.registrant_contact?.name ?? null
      const registrantOrg = rec.registrant_contact?.company ?? null
      const registrantEmail = rec.registrant_contact?.email ?? null
      const registrantCountry = rec.registrant_contact?.country_code ?? null

      const allFields = [registrantName, registrantOrg, registrantEmail]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
      const isPrivacy = PRIVACY_INDICATORS.some(p => allFields.includes(p))

      data.snapshots.push({
        snapshotDate: rec.query_time ?? '',
        registrantName,
        registrantOrg,
        registrantEmail,
        registrantCountry,
        registrar: rec.domain_registrar?.registrar_name ?? null,
        nameservers: rec.name_servers ?? [],
        createdDate: rec.create_date ?? null,
        updatedDate: rec.update_date ?? null,
        expiresDate: rec.expiry_date ?? null,
        isPrivacyProtected: isPrivacy,
      })
    }

    // sort by date
    data.snapshots.sort((a, b) => a.snapshotDate.localeCompare(b.snapshotDate))

    if (data.snapshots.length > 0) {
      data.oldestRecord = data.snapshots[0].snapshotDate
    }

    // find unredacted records
    const unredacted = data.snapshots.filter(s => !s.isPrivacyProtected && (s.registrantEmail || s.registrantName))
    data.hasUnredactedRecords = unredacted.length > 0

    // distinct registrants
    const seen = new Set<string>()
    for (const s of data.snapshots) {
      if (s.isPrivacyProtected) continue
      const key = [s.registrantName, s.registrantEmail, s.registrantOrg]
        .filter(Boolean)
        .join('|')
        .toLowerCase()
      if (key && !seen.has(key)) {
        seen.add(key)
        data.distinctRegistrants.push({
          name: s.registrantName,
          email: s.registrantEmail,
          org: s.registrantOrg,
          firstSeen: s.snapshotDate,
        })
      }
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    warnings.push(`WHOIS history failed: ${msg}`)
  }

  // signals
  const signals: Signal[] = []

  if (data.hasUnredactedRecords) {
    const first = data.distinctRegistrants[0]
    signals.push({
      source: 'whois_historical',
      observation: `historical registrant found: ${first?.name ?? first?.email ?? first?.org} (first seen: ${first?.firstSeen})`,
      score: 0.90,
      confidence: 0.85,
      informationBits: first?.email ? 20.0 : 12.0,
      rawData: JSON.stringify(data.distinctRegistrants),
      sourceUrl: url.replace(apiKey, 'REDACTED'),
    })
  }

  if (data.distinctRegistrants.length > 1) {
    signals.push({
      source: 'whois_historical',
      observation: `${data.distinctRegistrants.length} distinct registrants found across ${data.snapshots.length} historical records — ownership may have changed`,
      score: 0.60,
      confidence: 0.80,
      informationBits: 5.0,
      rawData: JSON.stringify(data.distinctRegistrants),
      sourceUrl: url.replace(apiKey, 'REDACTED'),
    })
  }

  return { data, signals, raw, url: url.replace(apiKey, 'REDACTED'), collectedAt, warnings }
}
