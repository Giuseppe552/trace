/**
 * HTTP header fingerprinting collector.
 *
 * Fetches a URL and extracts attribution-relevant headers.
 * The combination of server, framework, CDN, and unique headers
 * creates a fingerprint that can link domains to the same operator.
 *
 * Attribution value:
 * - Server + framework headers identify technology stack
 * - Unique headers (x-vercel-id, x-amz-request-id) identify hosting
 * - Analytics/tracking IDs (in CSP, meta tags) link sites to accounts
 * - Security header configuration patterns are operator-specific
 */

import type { CollectorResult, Signal, FetchOptions } from '../types.js'
import { fetchWithTimeout } from '../types.js'

/** Structured header fingerprint */
export interface HeaderFingerprint {
  url: string
  statusCode: number
  server: string | null
  poweredBy: string | null
  /** detected platform (vercel, cloudflare, aws, netlify, etc.) */
  platform: string | null
  /** all security headers present */
  securityHeaders: Record<string, string>
  /** all response headers */
  allHeaders: Record<string, string>
  /** tracking/analytics identifiers found in headers or CSP */
  trackingIds: Array<{ type: string; value: string }>
  /** technology stack inferred from headers */
  techStack: string[]
}

const PLATFORM_SIGNATURES: Array<{ header: string; pattern: RegExp; platform: string }> = [
  { header: 'x-vercel-id', pattern: /.+/, platform: 'vercel' },
  { header: 'x-vercel-cache', pattern: /.+/, platform: 'vercel' },
  { header: 'server', pattern: /cloudflare/i, platform: 'cloudflare' },
  { header: 'cf-ray', pattern: /.+/, platform: 'cloudflare' },
  { header: 'x-amz-request-id', pattern: /.+/, platform: 'aws' },
  { header: 'x-amz-cf-id', pattern: /.+/, platform: 'aws-cloudfront' },
  { header: 'x-served-by', pattern: /cache-.+\.fastly/, platform: 'fastly' },
  { header: 'x-netlify-request-id', pattern: /.+/, platform: 'netlify' },
  { header: 'x-github-request-id', pattern: /.+/, platform: 'github-pages' },
  { header: 'server', pattern: /nginx/i, platform: 'nginx' },
  { header: 'server', pattern: /apache/i, platform: 'apache' },
  { header: 'x-powered-by', pattern: /next\.js/i, platform: 'nextjs' },
  { header: 'x-powered-by', pattern: /express/i, platform: 'express' },
  { header: 'x-powered-by', pattern: /php/i, platform: 'php' },
]

const SECURITY_HEADERS = [
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'strict-transport-security',
  'permissions-policy',
  'x-xss-protection',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
]

const TRACKING_PATTERNS: Array<{ pattern: RegExp; type: string }> = [
  { pattern: /UA-\d{4,10}-\d{1,4}/, type: 'google-analytics-ua' },
  { pattern: /G-[A-Z0-9]{10,}/, type: 'google-analytics-ga4' },
  { pattern: /GTM-[A-Z0-9]{6,}/, type: 'google-tag-manager' },
  { pattern: /fbq\(['"]init['"],\s*['"](\d+)['"]/, type: 'facebook-pixel' },
  { pattern: /AW-\d{10,}/, type: 'google-ads' },
]

/**
 * Collect HTTP header fingerprint for a URL.
 */
export async function collectHeaders(
  url: string,
  options: FetchOptions = {},
): Promise<CollectorResult<HeaderFingerprint>> {
  const collectedAt = new Date().toISOString()
  const warnings: string[] = []

  // ensure https
  const targetUrl = url.startsWith('http') ? url : `https://${url}`

  let statusCode = 0
  const allHeaders: Record<string, string> = {}

  try {
    const resp = await fetchWithTimeout(targetUrl, options)
    statusCode = resp.status

    for (const [key, value] of resp.headers.entries()) {
      allHeaders[key.toLowerCase()] = value
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    warnings.push(`fetch failed: ${msg}`)
  }

  const server = allHeaders['server'] ?? null
  const poweredBy = allHeaders['x-powered-by'] ?? null

  // detect platform
  const platforms = new Set<string>()
  for (const sig of PLATFORM_SIGNATURES) {
    const headerVal = allHeaders[sig.header]
    if (headerVal && sig.pattern.test(headerVal)) {
      platforms.add(sig.platform)
    }
  }
  const platform = platforms.size > 0 ? [...platforms].join('+') : null

  // extract security headers
  const securityHeaders: Record<string, string> = {}
  for (const h of SECURITY_HEADERS) {
    if (allHeaders[h]) securityHeaders[h] = allHeaders[h]
  }

  // search for tracking IDs in all header values
  const trackingIds: Array<{ type: string; value: string }> = []
  const allHeaderValues = Object.values(allHeaders).join(' ')
  for (const { pattern, type } of TRACKING_PATTERNS) {
    const match = allHeaderValues.match(pattern)
    if (match) {
      trackingIds.push({ type, value: match[0] })
    }
  }

  // tech stack summary
  const techStack = [...platforms]
  if (allHeaders['x-powered-by']) techStack.push(allHeaders['x-powered-by'])

  const data: HeaderFingerprint = {
    url: targetUrl,
    statusCode,
    server,
    poweredBy,
    platform,
    securityHeaders,
    allHeaders,
    trackingIds,
    techStack,
  }

  const raw = JSON.stringify(data, null, 2)

  // build signals
  const signals: Signal[] = []

  if (platform) {
    signals.push({
      source: 'headers',
      observation: `platform: ${platform}`,
      score: 0.4,
      confidence: 0.95,
      informationBits: 2.0,
      rawData: platform,
      sourceUrl: targetUrl,
    })
  }

  if (trackingIds.length > 0) {
    // tracking IDs are very high-value — they link sites to specific accounts
    for (const tid of trackingIds) {
      signals.push({
        source: 'headers',
        observation: `${tid.type}: ${tid.value}`,
        score: 0.85,
        confidence: 0.95,
        informationBits: 15.0, // tracking ID is near-unique
        rawData: tid.value,
        sourceUrl: targetUrl,
      })
    }
  }

  // security header configuration as a fingerprint
  const secHeaderCount = Object.keys(securityHeaders).length
  if (secHeaderCount > 0) {
    signals.push({
      source: 'headers',
      observation: `${secHeaderCount} security headers configured`,
      score: 0.3,
      confidence: 0.8,
      informationBits: 1.0,
      rawData: Object.keys(securityHeaders).join(', '),
      sourceUrl: targetUrl,
    })
  }

  return { data, signals, raw, url: targetUrl, collectedAt, warnings }
}
