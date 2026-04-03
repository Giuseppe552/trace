/**
 * Calibration constants for signal reliability.
 *
 * Each collector imports the values it needs from here.
 * Single source of truth — change a calibration value once,
 * it propagates to every collector.
 *
 * Every value cites the study it was derived from.
 */

export const CAL = {
  // WHOIS
  WHOIS_VISIBLE: 0.92,
  WHOIS_VISIBLE_CITE: 'ICANN ARS Phase 2 Cycle 6, 2018: 92% registrant email operability',
  WHOIS_REDACTED: 0.10,
  WHOIS_REDACTED_CITE: 'WhoisXML API: 73% of gTLD domains have no registrant email post-GDPR',
  WHOIS_HISTORICAL: 0.85,
  WHOIS_HISTORICAL_CITE: 'ICANN ARS pre-GDPR accuracy; data may be stale',

  // CT
  CT: 0.87,
  CT_CITE: 'Li et al. CCS 2019: ~93% monitor completeness for crt.sh',

  // DNS
  DNS: 0.90,
  DNS_CITE: 'DNS records are factual; resolver accuracy is near-perfect',

  // Email
  EMAIL_AUTH: 0.85,
  EMAIL_AUTH_CITE: 'SPF+DKIM+DMARC pass verifies sending domain (RFC 7208/6376/7489)',
  EMAIL_PARTIAL: 0.60,
  EMAIL_PARTIAL_CITE: 'SPF pass alone; DKIM/DMARC absent or not aligned',
  EMAIL_FAILED: 0.40,
  EMAIL_FAILED_CITE: 'Auth failure indicates spoofing but does not identify sender',
  EMAIL_STRIPPED: 0.20,
  EMAIL_STRIPPED_CITE: 'Gmail/Outlook strip X-Originating-IP; minimal attribution value',

  // IP Geo
  IP_COUNTRY: 0.95,
  IP_COUNTRY_CITE: 'MaxMind: 99.8% country-level accuracy',
  IP_CITY_US_EU: 0.60,
  IP_CITY_US_EU_CITE: 'MaxMind: ~66% city-level accuracy within 50km (US)',
  IP_CITY_OTHER: 0.40,
  IP_CITY_OTHER_CITE: 'MaxMind: lower accuracy outside US/EU; no published number',
  IP_ASN: 0.90,
  IP_ASN_CITE: 'MaxMind: ~95% ISP accuracy (US), ~80% outside US',
  IP_PROXY: 0.20,
  IP_PROXY_CITE: 'Proxy/VPN masks real location; geolocation reflects exit node',

  // Stylometry
  STYLE_200: 0.75,
  STYLE_200_CITE: 'Abbasi & Chen ACM TOIS 26(2) 2008; arXiv 2507.00838: 79-100% on ~100 words',
  STYLE_100: 0.55,
  STYLE_100_CITE: 'Interpolated from Abbasi & Chen 2008 and arXiv 2507.00838',
  STYLE_50: 0.35,
  STYLE_50_CITE: 'arXiv 2003.11545: accuracy drops sharply below 100 words',
  STYLE_UNDER_50: 0.15,
  STYLE_UNDER_50_CITE: 'Literature consensus: unreliable below 50 words',

  // Review heuristics
  REVIEW_MULTI_FLAG: 0.65,
  REVIEW_MULTI_FLAG_CITE: 'Uncalibrated; convergent heuristic signals',
  REVIEW_SINGLE_FLAG: 0.35,
  REVIEW_SINGLE_FLAG_CITE: 'Uncalibrated; individual heuristic, high false positive risk',

  // Tracking IDs
  TRACKING_GA: 0.98,
  TRACKING_GA_CITE: 'GA property IDs are unique; shared = same account owner',

  // Headers / platform
  HEADERS_PLATFORM: 0.90,
  HEADERS_PLATFORM_CITE: 'Platform headers (x-vercel-id, cf-ray) are factual',
  HEADERS_TRACKING: 0.98,
  HEADERS_TRACKING_CITE: 'Analytics IDs are near-unique; shared = same account',
  HEADERS_SECURITY: 0.70,
  HEADERS_SECURITY_CITE: 'Security header configuration is operator-specific but not unique',

  // Correlation
  CORR_DEDICATED_IP: 0.85,
  CORR_DEDICATED_IP_CITE: 'Dedicated IP implies same hosting account',
  CORR_CDN_IP: 0.05,
  CORR_CDN_IP_CITE: 'CDN anycast IPs shared across thousands of unrelated domains',
  CORR_REGISTRANT: 0.95,
  CORR_REGISTRANT_CITE: 'ICANN ARS: unredacted registrant data is 92% accurate',
  CORR_TRACKING: 0.98,
  CORR_TRACKING_CITE: 'Analytics IDs are near-unique; shared = same account',

  // AI detection
  AI_DETECTION: 0.45,
  AI_DETECTION_CITE: 'Uncalibrated; no benchmark dataset; heuristic thresholds',

  // Timing
  TIMING_N20: 0.70,
  TIMING_N20_CITE: 'KS test: adequate power at n>=20 (alpha=0.05)',
  TIMING_N10: 0.50,
  TIMING_N10_CITE: 'KS test: reduced power at n=10-20',
  TIMING_UNDER_10: 0.25,
  TIMING_UNDER_10_CITE: 'KS test: low power below n=10; results unreliable',

  // Social
  SOCIAL_CONFIRMED: 0.85,
  SOCIAL_CONFIRMED_CITE: 'API-validated profile existence (GitHub, Reddit, HN)',
  SOCIAL_UNCONFIRMED: 0.50,
  SOCIAL_UNCONFIRMED_CITE: 'HTTP 200 without body validation; ~15% false positive on LinkedIn',

  // Backlinks
  BACKLINKS: 0.55,
  BACKLINKS_CITE: 'Uncalibrated; heuristic spam pattern matching',

  // Domain age
  AGE_WHOIS: 0.95,
  AGE_WHOIS_CITE: 'Creation date from WHOIS is authoritative',
  AGE_WAYBACK: 0.80,
  AGE_WAYBACK_CITE: 'First archive.org capture; domain may predate first crawl',
  AGE_CT: 0.85,
  AGE_CT_CITE: 'First CT entry; mandatory logging since 2018',

  // Archive
  ARCHIVE: 1.0,
  ARCHIVE_CITE: 'Archive.org is an independent third-party timestamp',
} as const

/**
 * Helper to compute stylometry reliability based on word count.
 */
export function stylometryReliability(wordCount: number): { value: number; cite: string } {
  if (wordCount >= 200) return { value: CAL.STYLE_200, cite: CAL.STYLE_200_CITE }
  if (wordCount >= 100) return { value: CAL.STYLE_100, cite: CAL.STYLE_100_CITE }
  if (wordCount >= 50) return { value: CAL.STYLE_50, cite: CAL.STYLE_50_CITE }
  return { value: CAL.STYLE_UNDER_50, cite: CAL.STYLE_UNDER_50_CITE }
}

/**
 * Helper to compute IP geo reliability based on context.
 */
export function ipGeoReliability(
  type: 'country' | 'city' | 'asn',
  countryCode: string | null,
  isProxy: boolean | null,
): { value: number; cite: string } {
  if (isProxy) return { value: CAL.IP_PROXY, cite: CAL.IP_PROXY_CITE }

  if (type === 'country') return { value: CAL.IP_COUNTRY, cite: CAL.IP_COUNTRY_CITE }
  if (type === 'asn') return { value: CAL.IP_ASN, cite: CAL.IP_ASN_CITE }

  // city — depends on region
  const usEu = ['US', 'GB', 'DE', 'FR', 'NL', 'IT', 'ES', 'CA', 'AU', 'SE', 'NO', 'DK', 'FI', 'BE', 'AT', 'CH', 'IE', 'PT', 'PL', 'CZ']
  if (countryCode && usEu.includes(countryCode)) {
    return { value: CAL.IP_CITY_US_EU, cite: CAL.IP_CITY_US_EU_CITE }
  }
  return { value: CAL.IP_CITY_OTHER, cite: CAL.IP_CITY_OTHER_CITE }
}

/**
 * Helper to compute timing reliability based on sample size.
 */
export function timingReliability(sampleSize: number): { value: number; cite: string } {
  if (sampleSize >= 20) return { value: CAL.TIMING_N20, cite: CAL.TIMING_N20_CITE }
  if (sampleSize >= 10) return { value: CAL.TIMING_N10, cite: CAL.TIMING_N10_CITE }
  return { value: CAL.TIMING_UNDER_10, cite: CAL.TIMING_UNDER_10_CITE }
}
