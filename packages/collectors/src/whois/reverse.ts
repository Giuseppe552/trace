/**
 * Reverse WHOIS lookup.
 *
 * Given an identifier (email, name, organization, phone), finds all
 * domains registered with that information. This is the highest-value
 * OSINT technique for mapping threat actor infrastructure — a single
 * shared registrant email surfaces the entire operation.
 *
 * Two backends:
 * 1. WhoisFreaks API (freemium, 100 free lookups/month)
 * 2. ViewDNS.info (free, HTML scraping — less reliable)
 *
 * Post-GDPR: many registrant details are now redacted. Historical
 * reverse WHOIS (pre-GDPR records) is more valuable. WhoisFreaks
 * supports historical queries.
 *
 * Reference: DomainTools Cybercrime Investigation Guide (APWG)
 *   "Pivoting on a shared registrant email is one of the most
 *   effective OSINT techniques for mapping threat actor infrastructure."
 */

import type { CollectorResult, Signal, FetchOptions } from '../types.js'
import { fetchWithTimeout } from '../types.js'

/** A domain found via reverse WHOIS */
export interface ReverseDomain {
  domain: string
  createdDate: string | null
  expiresDate: string | null
  registrar: string | null
}

/** Reverse WHOIS result */
export interface ReverseWhoisResult {
  /** what was searched */
  query: string
  /** type of search */
  queryType: 'email' | 'name' | 'organization' | 'phone'
  /** domains found */
  domains: ReverseDomain[]
  /** total count (may exceed returned results) */
  totalCount: number
  /** data source */
  source: string
}

/**
 * Reverse WHOIS via WhoisFreaks API.
 *
 * Requires API key. Free tier: 100 lookups/month.
 * Set WHOISFREAKS_API_KEY env var.
 *
 * Docs: https://whoisfreaks.com/tools/whois/reverse/search
 */
export async function reverseWhoisFreaks(
  query: string,
  queryType: ReverseWhoisResult['queryType'],
  options: FetchOptions & { apiKey?: string } = {},
): Promise<CollectorResult<ReverseWhoisResult>> {
  const apiKey = options.apiKey ?? process.env.WHOISFREAKS_API_KEY
  const collectedAt = new Date().toISOString()
  const warnings: string[] = []

  if (!apiKey) {
    warnings.push('WHOISFREAKS_API_KEY not set — reverse WHOIS unavailable')
    return {
      data: { query, queryType, domains: [], totalCount: 0, source: 'whoisfreaks' },
      signals: [],
      raw: '',
      url: '',
      collectedAt,
      warnings,
    }
  }

  const fieldMap: Record<string, string> = {
    email: 'email',
    name: 'owner',
    organization: 'company',
    phone: 'phone',
  }
  const field = fieldMap[queryType] ?? 'keyword'

  const url = `https://api.whoisfreaks.com/v1.0/whois?apiKey=${apiKey}&whois=reverse&${field}=${encodeURIComponent(query)}&mode=mini`
  let raw = ''

  const data: ReverseWhoisResult = {
    query,
    queryType,
    domains: [],
    totalCount: 0,
    source: 'whoisfreaks',
  }

  try {
    const resp = await fetchWithTimeout(url, { ...options, timeout: options.timeout ?? 15_000 })
    raw = await resp.text()

    if (!resp.ok) {
      warnings.push(`WhoisFreaks returned ${resp.status}`)
      return { data, signals: [], raw, url, collectedAt, warnings }
    }

    const json = JSON.parse(raw) as {
      total_count?: number
      whois_domains_historical?: Array<{
        domain_name?: string
        create_date?: string
        expiry_date?: string
        domain_registrar?: { registrar_name?: string }
      }>
    }

    data.totalCount = json.total_count ?? 0
    data.domains = (json.whois_domains_historical ?? []).map(d => ({
      domain: d.domain_name ?? '',
      createdDate: d.create_date ?? null,
      expiresDate: d.expiry_date ?? null,
      registrar: d.domain_registrar?.registrar_name ?? null,
    }))
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    warnings.push(`reverse WHOIS failed: ${msg}`)
  }

  const signals: Signal[] = []

  if (data.domains.length > 0) {
    signals.push({
      source: 'whois_reverse',
      observation: `${data.totalCount} domain(s) found registered with ${queryType}="${query}"`,
      score: 0.85,
      confidence: 0.90,
      informationBits: Math.min(20, Math.log2(data.totalCount + 1) + 10),
      rawData: data.domains.map(d => d.domain).join(', '),
      sourceUrl: url.replace(apiKey, 'REDACTED'),
    })
  }

  return { data, signals, raw, url: url.replace(apiKey, 'REDACTED'), collectedAt, warnings }
}

/**
 * Reverse WHOIS via ViewDNS.info (free, no API key).
 *
 * Parses HTML response. Less reliable, may be rate-limited.
 * Use as fallback when WhoisFreaks key isn't available.
 */
export async function reverseWhoisViewDns(
  query: string,
  options: FetchOptions = {},
): Promise<CollectorResult<ReverseWhoisResult>> {
  const url = `https://viewdns.info/reversewhois/?q=${encodeURIComponent(query)}`
  const collectedAt = new Date().toISOString()
  const warnings: string[] = []

  const data: ReverseWhoisResult = {
    query,
    queryType: 'email', // viewdns searches all fields
    domains: [],
    totalCount: 0,
    source: 'viewdns',
  }

  let raw = ''
  try {
    const resp = await fetchWithTimeout(url, {
      ...options,
      timeout: options.timeout ?? 15_000,
      headers: { Accept: 'text/html' },
    })
    raw = await resp.text()

    // parse table rows: each row has domain, created, registrar
    const tableMatch = raw.match(/<table[^>]*>([\s\S]*?)<\/table>/gi)
    if (tableMatch) {
      const rows = tableMatch[tableMatch.length - 1].match(/<tr[^>]*>([\s\S]*?)<\/tr>/gi) ?? []
      for (const row of rows.slice(1)) { // skip header row
        const cells = row.match(/<td[^>]*>([\s\S]*?)<\/td>/gi) ?? []
        if (cells.length >= 3) {
          const domain = cells[0]!.replace(/<[^>]+>/g, '').trim()
          const created = cells[1]!.replace(/<[^>]+>/g, '').trim()
          const registrar = cells[2]!.replace(/<[^>]+>/g, '').trim()
          if (domain && domain !== 'Domain Name') {
            data.domains.push({ domain, createdDate: created || null, expiresDate: null, registrar: registrar || null })
          }
        }
      }
    }

    data.totalCount = data.domains.length
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    warnings.push(`viewdns reverse WHOIS failed: ${msg}`)
  }

  const signals: Signal[] = []
  if (data.domains.length > 0) {
    signals.push({
      source: 'whois_reverse',
      observation: `${data.domains.length} domain(s) found associated with "${query}"`,
      score: 0.80,
      confidence: 0.75,
      informationBits: Math.min(18, Math.log2(data.domains.length + 1) + 8),
      rawData: data.domains.map(d => d.domain).join(', '),
      sourceUrl: url,
    })
  }

  return { data, signals, raw, url, collectedAt, warnings }
}
