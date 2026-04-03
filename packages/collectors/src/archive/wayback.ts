/**
 * Wayback Machine integration for evidence preservation.
 *
 * Saves URLs to the Internet Archive and retrieves archived snapshots.
 * Provides an independent, third-party timestamp for evidence.
 *
 * Per Berkeley Protocol: evidence should be preserved with independent
 * timestamps. The Wayback Machine is accepted in legal proceedings as
 * an independent archival service.
 *
 * Two operations:
 * 1. Save Now — trigger the Wayback Machine to archive a URL
 * 2. Check — verify if a URL has been previously archived
 */

import type { CollectorResult, Signal, FetchOptions } from '../types.js'
import { fetchWithTimeout } from '../types.js'

/** Result of an archive operation */
export interface ArchiveResult {
  /** the URL that was archived */
  originalUrl: string
  /** Wayback Machine URL of the archived version */
  archiveUrl: string | null
  /** when the archive was created */
  archiveTimestamp: string | null
  /** HTTP status of the archive request */
  status: 'saved' | 'already_exists' | 'error'
  /** error message if failed */
  error: string | null
}

/** Snapshot from availability check */
export interface ArchiveSnapshot {
  url: string
  archiveUrl: string
  timestamp: string
  status: string
}

/**
 * Save a URL to the Wayback Machine.
 *
 * Uses the Save Page Now API: https://web.archive.org/save/<url>
 * Rate-limited but free. May take 10-30 seconds.
 */
export async function archiveUrl(
  url: string,
  options: FetchOptions = {},
): Promise<CollectorResult<ArchiveResult>> {
  const saveUrl = `https://web.archive.org/save/${url}`
  const collectedAt = new Date().toISOString()
  const warnings: string[] = []
  let raw = ''

  const data: ArchiveResult = {
    originalUrl: url,
    archiveUrl: null,
    archiveTimestamp: null,
    status: 'error',
    error: null,
  }

  try {
    const resp = await fetchWithTimeout(saveUrl, {
      ...options,
      timeout: options.timeout ?? 30_000,
    })
    raw = `status: ${resp.status}`

    // the save endpoint returns a redirect to the archived page
    // or a 200 with the archive URL in the content-location header
    const archiveLocation = resp.headers.get('content-location')
      ?? resp.headers.get('location')

    if (archiveLocation) {
      data.archiveUrl = `https://web.archive.org${archiveLocation}`
      data.archiveTimestamp = collectedAt
      data.status = 'saved'
    } else if (resp.ok) {
      // try to extract from the response URL
      data.archiveUrl = resp.url.includes('web.archive.org') ? resp.url : null
      data.archiveTimestamp = collectedAt
      data.status = data.archiveUrl ? 'saved' : 'error'
    } else {
      data.error = `HTTP ${resp.status}`
      warnings.push(`archive.org returned ${resp.status}`)
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    data.error = msg
    warnings.push(`archive save failed: ${msg}`)
  }

  const signals: Signal[] = []
  if (data.status === 'saved' && data.archiveUrl) {
    signals.push({
      source: 'archive',
      observation: `page archived at ${data.archiveUrl}`,
      score: 0,
      confidence: 1.0,
      informationBits: 0, // archival doesn't add attribution info
      rawData: data.archiveUrl,
      sourceUrl: saveUrl,
    })
  }

  return { data, signals, raw, url: saveUrl, collectedAt, warnings }
}

/**
 * Check if a URL has been previously archived.
 *
 * Uses the Availability API: https://archive.org/wayback/available?url=<url>
 */
export async function checkArchive(
  url: string,
  options: FetchOptions = {},
): Promise<ArchiveSnapshot | null> {
  const apiUrl = `https://archive.org/wayback/available?url=${encodeURIComponent(url)}`

  try {
    const resp = await fetchWithTimeout(apiUrl, options)
    const json = await resp.json() as {
      archived_snapshots?: {
        closest?: { url: string; timestamp: string; status: string; available: boolean }
      }
    }

    const snapshot = json.archived_snapshots?.closest
    if (!snapshot?.available) return null

    // convert timestamp "20260402120000" → ISO
    const ts = snapshot.timestamp
    const isoTimestamp = ts.length >= 14
      ? `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}T${ts.slice(8, 10)}:${ts.slice(10, 12)}:${ts.slice(12, 14)}Z`
      : ts

    return {
      url,
      archiveUrl: snapshot.url,
      timestamp: isoTimestamp,
      status: snapshot.status,
    }
  } catch {
    return null
  }
}

/**
 * Archive multiple URLs for evidence preservation.
 * Sequential with delays to respect rate limits.
 */
export async function archiveMultiple(
  urls: string[],
  options: FetchOptions = {},
): Promise<Array<CollectorResult<ArchiveResult>>> {
  const results: Array<CollectorResult<ArchiveResult>> = []

  for (const url of urls) {
    results.push(await archiveUrl(url, options))
    // archive.org rate limit — be respectful
    await new Promise(r => setTimeout(r, 5000))
  }

  return results
}
