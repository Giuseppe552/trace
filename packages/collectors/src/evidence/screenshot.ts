/**
 * Evidence screenshot capture.
 *
 * Captures web pages as evidence with metadata for legal proceedings.
 * Two approaches:
 * 1. HTML snapshot (fetch + save complete HTML)
 * 2. Archive.org preservation (independent third-party timestamp)
 *
 * Per Berkeley Protocol: screenshots must include:
 * - Full URL visible
 * - Timestamp of capture
 * - Hash of captured content
 * - Analyst identity
 *
 * This module doesn't use Playwright/Puppeteer (heavy deps).
 * For full visual screenshots, use the separate screenshot tool
 * or archive.org which captures rendered pages.
 */

import type { Signal, FetchOptions } from '../types.js'
import { fetchWithTimeout } from '../types.js'
import { sha256, type EvidenceChain, appendEvidence } from '@trace/core'

/** A captured page */
export interface PageCapture {
  url: string
  capturedAt: string
  /** HTTP status code */
  statusCode: number
  /** all response headers */
  headers: Record<string, string>
  /** full HTML body */
  html: string
  /** SHA-256 hash of the HTML body */
  contentHash: string
  /** page title extracted from HTML */
  title: string | null
  /** content length in bytes */
  contentLength: number
  /** was the page successfully captured? */
  success: boolean
  /** archive.org URL if preserved */
  archiveUrl: string | null
}

/**
 * Capture a web page as evidence.
 *
 * Fetches the complete HTML and computes a SHA-256 hash.
 * Optionally saves to archive.org for independent verification.
 */
export async function capturePage(
  url: string,
  options: FetchOptions & {
    /** also save to archive.org */
    archive?: boolean
    /** evidence chain to append to */
    chain?: EvidenceChain
  } = {},
): Promise<PageCapture> {
  const capturedAt = new Date().toISOString()
  const targetUrl = url.startsWith('http') ? url : `https://${url}`

  let statusCode = 0
  let html = ''
  const headers: Record<string, string> = {}
  let success = false

  try {
    const resp = await fetchWithTimeout(targetUrl, {
      ...options,
      timeout: options.timeout ?? 15_000,
    })
    statusCode = resp.status
    html = await resp.text()
    success = resp.ok

    for (const [key, value] of resp.headers.entries()) {
      headers[key.toLowerCase()] = value
    }
  } catch (err) {
    html = `capture failed: ${err instanceof Error ? err.message : String(err)}`
  }

  const contentHash = await sha256(html)

  // extract title
  let title: string | null = null
  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)
  if (titleMatch) title = titleMatch[1].trim()

  // archive.org preservation
  let archiveUrl: string | null = null
  if (options.archive && success) {
    try {
      const archiveResp = await fetchWithTimeout(
        `https://web.archive.org/save/${targetUrl}`,
        { timeout: 30_000 },
      )
      const location = archiveResp.headers.get('content-location')
        ?? archiveResp.headers.get('location')
      if (location) {
        archiveUrl = `https://web.archive.org${location}`
      }
    } catch { /* non-fatal */ }
  }

  const capture: PageCapture = {
    url: targetUrl,
    capturedAt,
    statusCode,
    headers,
    html,
    contentHash,
    title,
    contentLength: new TextEncoder().encode(html).length,
    success,
    archiveUrl,
  }

  // append to evidence chain if provided
  if (options.chain) {
    await appendEvidence(options.chain, {
      content: html,
      type: 'html',
      source: targetUrl,
      description: `page capture: ${title ?? targetUrl} (${statusCode}, ${capture.contentLength} bytes, hash: ${contentHash.slice(0, 12)}...)`,
      layer: 'evidence',
    })

    if (archiveUrl) {
      await appendEvidence(options.chain, {
        content: archiveUrl,
        type: 'archive_url',
        source: archiveUrl,
        description: `archived at ${archiveUrl}`,
        layer: 'evidence',
      })
    }
  }

  return capture
}

/**
 * Capture multiple pages as evidence.
 */
export async function captureMultiple(
  urls: string[],
  options: FetchOptions & { archive?: boolean; chain?: EvidenceChain } = {},
): Promise<PageCapture[]> {
  const results: PageCapture[] = []

  for (const url of urls) {
    results.push(await capturePage(url, options))
    await new Promise(r => setTimeout(r, 1000))
  }

  return results
}
