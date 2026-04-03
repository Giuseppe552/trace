/**
 * Domain age estimation from multiple sources.
 *
 * Domain age is a strong attribution signal:
 * - Domains registered days before an attack → purpose-built for the attack
 * - Domains registered years ago → established, likely legitimate
 *
 * Sources (in order of reliability):
 * 1. WHOIS creation date (most reliable but often redacted)
 * 2. Wayback Machine first capture (public, free)
 * 3. CT log first certificate (crt.sh, free)
 *
 * A domain registered 3 days before a burst of fake reviews
 * from that domain's email is highly suspicious.
 */

import type { Signal, FetchOptions } from '../types.js'
import { fetchWithTimeout } from '../types.js'

/** Domain age estimation */
export interface DomainAge {
  domain: string
  /** WHOIS creation date if available */
  whoisCreated: string | null
  /** first Wayback Machine capture */
  waybackFirst: string | null
  /** first CT log entry */
  ctFirst: string | null
  /** best estimate of domain age in days */
  estimatedAgeDays: number | null
  /** which source provided the age estimate */
  ageSource: 'whois' | 'wayback' | 'ct' | 'unknown'
  /** age classification */
  category: 'brand_new' | 'very_fresh' | 'fresh' | 'moderate' | 'established' | 'unknown'
}

/**
 * Estimate domain age from Wayback Machine availability.
 *
 * Uses the Wayback CDX API for the earliest capture timestamp.
 */
async function waybackFirstCapture(
  domain: string,
  options: FetchOptions = {},
): Promise<string | null> {
  const url = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}&output=json&limit=1&fl=timestamp&sort=timestamp:asc`

  try {
    const resp = await fetchWithTimeout(url, { ...options, timeout: 10_000 })
    const json = await resp.json() as string[][]
    if (json.length >= 2 && json[1]?.[0]) {
      const ts = json[1][0]
      return `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`
    }
  } catch { /* non-fatal */ }

  return null
}

/**
 * Get first CT log entry date for a domain.
 */
async function ctFirstEntry(
  domain: string,
  options: FetchOptions = {},
): Promise<string | null> {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`

  try {
    const resp = await fetchWithTimeout(url, { ...options, timeout: 15_000 })
    const json = await resp.json() as Array<{ not_before?: string }>
    if (json.length > 0) {
      const dates = json
        .map(e => e.not_before)
        .filter(Boolean)
        .sort() as string[]
      return dates[0]?.slice(0, 10) ?? null
    }
  } catch { /* non-fatal */ }

  return null
}

function daysSince(dateStr: string): number {
  const then = new Date(dateStr).getTime()
  if (isNaN(then)) return -1
  return Math.floor((Date.now() - then) / (86400 * 1000))
}

function categorize(days: number): DomainAge['category'] {
  if (days < 0) return 'unknown'
  if (days <= 7) return 'brand_new'
  if (days <= 30) return 'very_fresh'
  if (days <= 90) return 'fresh'
  if (days <= 365) return 'moderate'
  return 'established'
}

/**
 * Estimate the age of a domain using multiple sources.
 */
export async function estimateDomainAge(
  domain: string,
  options: FetchOptions & { whoisCreated?: string } = {},
): Promise<{ data: DomainAge; signals: Signal[] }> {
  const data: DomainAge = {
    domain,
    whoisCreated: options.whoisCreated ?? null,
    waybackFirst: null,
    ctFirst: null,
    estimatedAgeDays: null,
    ageSource: 'unknown',
    category: 'unknown',
  }

  // collect from all sources in parallel
  const [wayback, ct] = await Promise.allSettled([
    waybackFirstCapture(domain, options),
    ctFirstEntry(domain, options),
  ])

  if (wayback.status === 'fulfilled') data.waybackFirst = wayback.value
  if (ct.status === 'fulfilled') data.ctFirst = ct.value

  // pick the earliest date from available sources
  const dates: Array<{ source: DomainAge['ageSource']; date: string }> = []
  if (data.whoisCreated) dates.push({ source: 'whois', date: data.whoisCreated })
  if (data.waybackFirst) dates.push({ source: 'wayback', date: data.waybackFirst })
  if (data.ctFirst) dates.push({ source: 'ct', date: data.ctFirst })

  if (dates.length > 0) {
    dates.sort((a, b) => a.date.localeCompare(b.date))
    const earliest = dates[0]
    data.estimatedAgeDays = daysSince(earliest.date)
    data.ageSource = earliest.source
    data.category = categorize(data.estimatedAgeDays)
  }

  const signals: Signal[] = []

  if (data.estimatedAgeDays !== null) {
    const severity = data.category === 'brand_new' ? 'high' :
      data.category === 'very_fresh' ? 'medium' : 'low'

    if (data.category === 'brand_new' || data.category === 'very_fresh') {
      signals.push({
        source: 'domain_age',
        observation: `${domain} is ${data.category.replace('_', ' ')} (${data.estimatedAgeDays} days, source: ${data.ageSource})`,
        score: data.category === 'brand_new' ? 0.8 : 0.5,
        confidence: data.ageSource === 'whois' ? 0.95 : 0.75,
        informationBits: data.category === 'brand_new' ? 5.0 : 3.0,
        rawData: JSON.stringify(data),
        sourceUrl: `domain-age:${domain}`,
      })
    }
  }

  return { data, signals }
}

/**
 * Check ages of multiple domains and flag suspiciously new ones.
 */
export async function batchDomainAge(
  domains: string[],
  options: FetchOptions = {},
): Promise<Array<{ data: DomainAge; signals: Signal[] }>> {
  const results: Array<{ data: DomainAge; signals: Signal[] }> = []

  for (const domain of domains) {
    results.push(await estimateDomainAge(domain, options))
    // rate limit
    await new Promise(r => setTimeout(r, 2000))
  }

  return results
}
