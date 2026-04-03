/**
 * IP geolocation and ASN lookup.
 *
 * Maps IP addresses to:
 * - Geographic location (country, city, coordinates)
 * - ASN (hosting provider / ISP)
 * - Organization name
 * - Hosting vs residential classification
 *
 * Uses free APIs (no key required):
 * - ip-api.com: 45 requests/minute, JSON, country/city/ISP/ASN
 * - ipinfo.io: 50k/month free tier (needs token for more)
 *
 * Attribution value:
 * - Country narrows anonymity set significantly (UK = 67M → UK pop)
 * - City narrows further (Bradford = 540K)
 * - ASN reveals hosting provider: shared hosting is weak signal,
 *   dedicated server is strong
 * - Residential vs datacenter IP distinguishes VPN/proxy from real location
 */

import type { CollectorResult, Signal, FetchOptions } from '../types.js'
import { fetchWithTimeout } from '../types.js'
import { ipGeoReliability } from '../calibration.js'

/** IP geolocation result */
export interface IpGeoResult {
  ip: string
  /** ISO 3166-1 alpha-2 country code */
  countryCode: string | null
  country: string | null
  region: string | null
  city: string | null
  lat: number | null
  lon: number | null
  /** ISP name */
  isp: string | null
  /** organization (may differ from ISP) */
  org: string | null
  /** AS number */
  asn: number | null
  /** AS name */
  asName: string | null
  /** is this IP from a hosting/datacenter provider? */
  isHosting: boolean | null
  /** is this IP a known proxy/VPN? */
  isProxy: boolean | null
  /** timezone */
  timezone: string | null
}

/** Known hosting/datacenter ASNs */
const HOSTING_ASNS = new Set([
  13335,  // Cloudflare
  16509,  // Amazon AWS
  14618,  // Amazon
  15169,  // Google
  8075,   // Microsoft Azure
  20940,  // Akamai
  54113,  // Fastly
  24940,  // Hetzner
  63949,  // Linode/Akamai
  14061,  // DigitalOcean
  16276,  // OVH
  51167,  // Contabo
  24940,  // Hetzner
  197540, // Netcup
  46606,  // Unified Layer
  36352,  // ColoCrossing
  55286,  // B2 Net Solutions (budget hosting)
  209,    // CenturyLink
  174,    // Cogent
])

const KNOWN_VPNS = new Set([
  'NordVPN', 'ExpressVPN', 'Surfshark', 'Private Internet Access',
  'Mullvad', 'ProtonVPN', 'CyberGhost', 'IPVanish', 'TorGuard',
])

/**
 * Look up IP geolocation via ip-api.com (free, 45 req/min).
 */
export async function lookupIp(
  ip: string,
  options: FetchOptions = {},
): Promise<CollectorResult<IpGeoResult>> {
  const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,asname,hosting,proxy,query`
  const collectedAt = new Date().toISOString()
  const warnings: string[] = []

  const data: IpGeoResult = {
    ip,
    countryCode: null, country: null, region: null, city: null,
    lat: null, lon: null, isp: null, org: null,
    asn: null, asName: null, isHosting: null, isProxy: null,
    timezone: null,
  }

  let raw = ''
  try {
    const resp = await fetchWithTimeout(url, options)
    raw = await resp.text()
    const json = JSON.parse(raw) as Record<string, unknown>

    if (json.status === 'fail') {
      warnings.push(`ip-api error: ${json.message}`)
      return { data, signals: [], raw, url, collectedAt, warnings }
    }

    data.countryCode = (json.countryCode as string) ?? null
    data.country = (json.country as string) ?? null
    data.region = (json.regionName as string) ?? null
    data.city = (json.city as string) ?? null
    data.lat = (json.lat as number) ?? null
    data.lon = (json.lon as number) ?? null
    data.isp = (json.isp as string) ?? null
    data.org = (json.org as string) ?? null
    data.timezone = (json.timezone as string) ?? null
    data.isHosting = (json.hosting as boolean) ?? null
    data.isProxy = (json.proxy as boolean) ?? null

    // parse ASN from "AS13335 Cloudflare, Inc."
    const asStr = (json.as as string) ?? ''
    const asMatch = asStr.match(/^AS(\d+)/)
    if (asMatch) data.asn = parseInt(asMatch[1], 10)
    data.asName = (json.asname as string) ?? null

    // enhance hosting detection
    if (data.asn && HOSTING_ASNS.has(data.asn)) {
      data.isHosting = true
    }
    if (data.org && KNOWN_VPNS.has(data.org)) {
      data.isProxy = true
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    warnings.push(`IP lookup failed: ${msg}`)
  }

  // build signals
  const signals: Signal[] = []

  if (data.country) {
    const COUNTRY_POP: Record<string, number> = {
      GB: 67_000_000, US: 334_000_000, DE: 84_000_000, FR: 68_000_000,
      IT: 59_000_000, ES: 47_000_000, NL: 17_500_000, PL: 38_000_000,
      CA: 38_000_000, AU: 26_000_000, IN: 1_400_000_000, BR: 215_000_000,
      JP: 125_000_000, RU: 144_000_000, CN: 1_400_000_000,
    }
    const countryPop = COUNTRY_POP[data.countryCode ?? ''] ?? 50_000_000
    const worldPop = 8_000_000_000
    const gain = Math.log2(worldPop / countryPop)
    const countryRel = ipGeoReliability('country', data.countryCode, data.isProxy)

    signals.push({
      source: 'ip_geo',
      observation: `country: ${data.country} (${data.countryCode})`,
      score: 0.5,
      confidence: data.isProxy ? 0.30 : 0.85,
      reliability: countryRel.value,
      reliabilityCitation: countryRel.cite,
      informationBits: gain,
      rawData: `${data.country} (${data.countryCode})`,
      sourceUrl: url,
    })
  }

  if (data.city) {
    const cityRel = ipGeoReliability('city', data.countryCode, data.isProxy)
    signals.push({
      source: 'ip_geo',
      observation: `city: ${data.city}, ${data.region}`,
      score: 0.6,
      confidence: data.isProxy ? 0.20 : 0.70,
      reliability: cityRel.value,
      reliabilityCitation: cityRel.cite,
      informationBits: 8.0,
      rawData: `${data.city}, ${data.region}, ${data.country}`,
      sourceUrl: url,
    })
  }

  if (data.asName) {
    const asnRel = ipGeoReliability('asn', data.countryCode, data.isProxy)
    signals.push({
      source: 'ip_geo',
      observation: `ASN: AS${data.asn} ${data.asName}`,
      score: data.isHosting ? 0.3 : 0.5,
      confidence: 0.95,
      reliability: asnRel.value,
      reliabilityCitation: asnRel.cite,
      informationBits: 2.0,
      rawData: `AS${data.asn} ${data.asName}`,
      sourceUrl: url,
    })
  }

  if (data.isHosting) {
    const hostRel = ipGeoReliability('asn', data.countryCode, false)
    signals.push({
      source: 'ip_geo',
      observation: 'datacenter/hosting IP — not a residential connection',
      score: 0.3,
      confidence: 0.90,
      reliability: hostRel.value,
      reliabilityCitation: hostRel.cite,
      informationBits: 1.0,
      rawData: `hosting=true, ASN=${data.asn}`,
      sourceUrl: url,
    })
  }

  if (data.isProxy) {
    const proxyRel = ipGeoReliability('country', data.countryCode, true)
    signals.push({
      source: 'ip_geo',
      observation: 'proxy/VPN detected — location data unreliable',
      score: 0.2,
      confidence: 0.80,
      reliability: proxyRel.value,
      reliabilityCitation: proxyRel.cite,
      informationBits: 0.5,
      rawData: `proxy=true, org=${data.org}`,
      sourceUrl: url,
    })
  }

  return { data, signals, raw, url, collectedAt, warnings }
}

/**
 * Batch lookup multiple IPs and correlate.
 * Returns shared hosting signals when multiple IPs resolve to the same ASN/org.
 */
export async function correlateIps(
  ips: string[],
  options: FetchOptions = {},
): Promise<{
  results: Array<CollectorResult<IpGeoResult>>
  correlations: Array<{ ips: string[]; sharedAttribute: string; value: string }>
}> {
  const results: Array<CollectorResult<IpGeoResult>> = []

  // ip-api allows batch requests but free tier is 45/min
  // sequential with small delay to stay under rate limit
  for (const ip of ips) {
    results.push(await lookupIp(ip, options))
    if (ips.length > 5) {
      await new Promise(r => setTimeout(r, 1500)) // rate limit safety
    }
  }

  // find correlations
  const correlations: Array<{ ips: string[]; sharedAttribute: string; value: string }> = []

  // shared ASN
  const byAsn = new Map<number, string[]>()
  for (const r of results) {
    if (r.data.asn) {
      const list = byAsn.get(r.data.asn) ?? []
      list.push(r.data.ip)
      byAsn.set(r.data.asn, list)
    }
  }
  for (const [asn, ips] of byAsn) {
    if (ips.length > 1) {
      const asName = results.find(r => r.data.asn === asn)?.data.asName ?? ''
      correlations.push({ ips, sharedAttribute: 'asn', value: `AS${asn} ${asName}` })
    }
  }

  // shared city
  const byCity = new Map<string, string[]>()
  for (const r of results) {
    if (r.data.city && r.data.countryCode) {
      const key = `${r.data.city},${r.data.countryCode}`
      const list = byCity.get(key) ?? []
      list.push(r.data.ip)
      byCity.set(key, list)
    }
  }
  for (const [city, ips] of byCity) {
    if (ips.length > 1) {
      correlations.push({ ips, sharedAttribute: 'city', value: city })
    }
  }

  // shared org
  const byOrg = new Map<string, string[]>()
  for (const r of results) {
    if (r.data.org) {
      const list = byOrg.get(r.data.org) ?? []
      list.push(r.data.ip)
      byOrg.set(r.data.org, list)
    }
  }
  for (const [org, ips] of byOrg) {
    if (ips.length > 1) {
      correlations.push({ ips, sharedAttribute: 'org', value: org })
    }
  }

  return { results, correlations }
}
