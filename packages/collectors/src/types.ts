/**
 * Shared types for all collectors.
 *
 * Every collector follows the same contract:
 * 1. Takes a target identifier (domain, email, IP, etc.)
 * 2. Returns structured data + raw response for evidence chain
 * 3. Reports attribution signals with confidence scores
 * 4. Never requires authentication for core functionality (public OSINT only)
 */

/** Attribution signal from a collector */
export interface Signal {
  /** which collector produced this */
  source: string
  /** what was observed */
  observation: string
  /** attribution score: how strongly this points to a suspect (0-1) */
  score: number
  /** confidence in the measurement (0-1) */
  confidence: number
  /** information gain in bits (for anonymity computation) */
  informationBits: number
  /** raw data for evidence chain */
  rawData: string
  /** source URL for evidence preservation */
  sourceUrl: string
}

/** Result from any collector */
export interface CollectorResult<T = unknown> {
  /** structured data specific to this collector */
  data: T
  /** attribution signals extracted */
  signals: Signal[]
  /** raw response for evidence chain */
  raw: string
  /** source URL */
  url: string
  /** timestamp of collection */
  collectedAt: string
  /** errors encountered (non-fatal) */
  warnings: string[]
}

/** HTTP fetch options shared across collectors */
export interface FetchOptions {
  /** timeout in ms (default 10000) */
  timeout?: number
  /** custom user-agent */
  userAgent?: string
  /** additional headers */
  headers?: Record<string, string>
}

const DEFAULT_UA = 'trace/0.1 (https://giuseppegiona.com; security research)'
const DEFAULT_TIMEOUT = 10_000

/**
 * Fetch with timeout and default headers.
 * All collectors use this — single point for OPSEC controls.
 */
export async function fetchWithTimeout(
  url: string,
  options: FetchOptions = {},
): Promise<Response> {
  const { timeout = DEFAULT_TIMEOUT, userAgent = DEFAULT_UA, headers = {} } = options

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeout)

  try {
    return await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': userAgent,
        Accept: 'application/json, text/plain, */*',
        ...headers,
      },
    })
  } finally {
    clearTimeout(timer)
  }
}
