/**
 * Email header forensic parser.
 *
 * Parses raw email headers (from .eml files or copy-paste) and extracts:
 * - Originating IP address
 * - Full routing path (Received headers, bottom to top)
 * - Authentication results (SPF, DKIM, DMARC)
 * - Sending infrastructure (Message-ID domain, Return-Path)
 * - Timestamp analysis for consistency checks
 *
 * Limitation: Gmail, Outlook, Yahoo strip X-Originating-IP.
 * Works best with custom domains and smaller providers.
 *
 * Reference: RFC 5322 (Internet Message Format)
 * Reference: RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC)
 */

import type { CollectorResult, Signal } from '../types.js'

/** A single Received hop in the routing chain */
export interface ReceivedHop {
  /** which server received the message */
  by: string
  /** which server sent it (may be IP or hostname) */
  from: string | null
  /** protocol used (SMTP, ESMTP, ESMTPS, etc.) */
  protocol: string | null
  /** timestamp of this hop */
  timestamp: string | null
  /** raw header value */
  raw: string
}

/** Structured email header analysis */
export interface EmailHeaderAnalysis {
  /** originating IP (X-Originating-IP or first Received hop) */
  originatingIp: string | null
  /** full routing path, chronological order (first = origin) */
  receivedChain: ReceivedHop[]
  /** claimed sender (From header) */
  from: string | null
  /** return path (bounce address) */
  returnPath: string | null
  /** Message-ID (domain reveals sending infrastructure) */
  messageId: string | null
  /** domain from Message-ID */
  messageIdDomain: string | null
  /** SPF result */
  spf: string | null
  /** DKIM result */
  dkim: string | null
  /** DMARC result */
  dmarc: string | null
  /** all X-Mailer / User-Agent headers */
  mailer: string | null
  /** timestamp anomalies detected */
  timestampAnomalies: string[]
  /** raw headers text */
  rawHeaders: string
}

/**
 * Parse raw email headers into structured analysis.
 *
 * @param rawHeaders - Full email headers as text (from "Show Original" in Gmail, etc.)
 */
export function parseEmailHeaders(rawHeaders: string): EmailHeaderAnalysis {
  const lines = rawHeaders.split(/\r?\n/)
  const timestampAnomalies: string[] = []

  // unfold continued headers (lines starting with whitespace)
  const unfolded: string[] = []
  for (const line of lines) {
    if (/^\s/.test(line) && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += ' ' + line.trim()
    } else {
      unfolded.push(line)
    }
  }

  // extract header values
  const getHeader = (name: string): string | null => {
    const re = new RegExp(`^${name}:\\s*(.+)`, 'im')
    for (const line of unfolded) {
      const match = line.match(re)
      if (match) return match[1].trim()
    }
    return null
  }

  const getAllHeaders = (name: string): string[] => {
    const results: string[] = []
    const re = new RegExp(`^${name}:\\s*(.+)`, 'i')
    for (const line of unfolded) {
      const match = line.match(re)
      if (match) results.push(match[1].trim())
    }
    return results
  }

  // originating IP
  let originatingIp = getHeader('X-Originating-IP')
  if (originatingIp) {
    originatingIp = originatingIp.replace(/[\[\]]/g, '').trim()
  }

  // parse Received headers (they appear in reverse order — last added is first)
  const receivedHeaders = getAllHeaders('Received')
  const receivedChain: ReceivedHop[] = receivedHeaders
    .map(parseReceivedHeader)
    .reverse() // chronological order

  // if no X-Originating-IP, use the first Received hop's from IP
  if (!originatingIp && receivedChain.length > 0) {
    const firstHop = receivedChain[0]
    if (firstHop.from) {
      const ipMatch = firstHop.from.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/)
      if (ipMatch) originatingIp = ipMatch[1]
    }
  }

  // From
  const from = getHeader('From')

  // Return-Path
  const returnPath = getHeader('Return-Path')?.replace(/[<>]/g, '') ?? null

  // Message-ID
  const messageId = getHeader('Message-ID')?.replace(/[<>]/g, '') ?? null
  let messageIdDomain: string | null = null
  if (messageId) {
    const atIdx = messageId.lastIndexOf('@')
    if (atIdx >= 0) messageIdDomain = messageId.slice(atIdx + 1)
  }

  // Authentication results
  const authResults = getHeader('Authentication-Results') ?? ''
  const spf = extractAuthResult(authResults, 'spf')
  const dkim = extractAuthResult(authResults, 'dkim')
  const dmarc = extractAuthResult(authResults, 'dmarc')

  // Mailer
  const mailer = getHeader('X-Mailer') ?? getHeader('User-Agent')

  // timestamp consistency check
  const hopTimestamps = receivedChain
    .map(h => h.timestamp ? new Date(h.timestamp).getTime() : NaN)
    .filter(t => !isNaN(t))

  for (let i = 1; i < hopTimestamps.length; i++) {
    if (hopTimestamps[i] < hopTimestamps[i - 1] - 60_000) {
      timestampAnomalies.push(
        `hop ${i} timestamp (${new Date(hopTimestamps[i]).toISOString()}) is before hop ${i - 1} (${new Date(hopTimestamps[i - 1]).toISOString()}) — possible spoofing`,
      )
    }
  }

  return {
    originatingIp,
    receivedChain,
    from,
    returnPath,
    messageId,
    messageIdDomain,
    spf,
    dkim,
    dmarc,
    mailer,
    timestampAnomalies,
    rawHeaders,
  }
}

function parseReceivedHeader(raw: string): ReceivedHop {
  const fromMatch = raw.match(/from\s+(\S+)/i)
  const byMatch = raw.match(/by\s+(\S+)/i)
  const withMatch = raw.match(/with\s+(\S+)/i)
  const dateMatch = raw.match(/;\s*(.+)$/)

  return {
    from: fromMatch?.[1] ?? null,
    by: byMatch?.[1] ?? 'unknown',
    protocol: withMatch?.[1] ?? null,
    timestamp: dateMatch?.[1]?.trim() ?? null,
    raw,
  }
}

function extractAuthResult(authResults: string, mechanism: string): string | null {
  const re = new RegExp(`${mechanism}=(\\w+)`, 'i')
  const match = authResults.match(re)
  return match?.[1] ?? null
}

/**
 * Analyze parsed email headers and produce attribution signals.
 */
export function collectEmailSignals(analysis: EmailHeaderAnalysis): CollectorResult<EmailHeaderAnalysis> {
  const signals: Signal[] = []
  const collectedAt = new Date().toISOString()

  if (analysis.originatingIp) {
    signals.push({
      source: 'email_headers',
      observation: `originating IP: ${analysis.originatingIp}`,
      score: 0.75,
      confidence: 0.80,
      informationBits: 15.0, // IP narrows significantly
      rawData: analysis.originatingIp,
      sourceUrl: 'email-header-analysis',
    })
  }

  if (analysis.returnPath) {
    signals.push({
      source: 'email_headers',
      observation: `return path: ${analysis.returnPath}`,
      score: 0.70,
      confidence: 0.85,
      informationBits: 12.0,
      rawData: analysis.returnPath,
      sourceUrl: 'email-header-analysis',
    })
  }

  if (analysis.messageIdDomain) {
    signals.push({
      source: 'email_headers',
      observation: `message-ID domain: ${analysis.messageIdDomain}`,
      score: 0.60,
      confidence: 0.75,
      informationBits: 8.0,
      rawData: analysis.messageIdDomain,
      sourceUrl: 'email-header-analysis',
    })
  }

  if (analysis.spf === 'fail' || analysis.dkim === 'fail' || analysis.dmarc === 'fail') {
    signals.push({
      source: 'email_headers',
      observation: `authentication failure: SPF=${analysis.spf}, DKIM=${analysis.dkim}, DMARC=${analysis.dmarc}`,
      score: 0.40,
      confidence: 0.90,
      informationBits: 2.0,
      rawData: `SPF=${analysis.spf},DKIM=${analysis.dkim},DMARC=${analysis.dmarc}`,
      sourceUrl: 'email-header-analysis',
    })
  }

  if (analysis.timestampAnomalies.length > 0) {
    signals.push({
      source: 'email_headers',
      observation: `${analysis.timestampAnomalies.length} timestamp anomalies detected — possible header spoofing`,
      score: 0.30,
      confidence: 0.70,
      informationBits: 1.5,
      rawData: analysis.timestampAnomalies.join('; '),
      sourceUrl: 'email-header-analysis',
    })
  }

  if (analysis.mailer) {
    signals.push({
      source: 'email_headers',
      observation: `mailer: ${analysis.mailer}`,
      score: 0.35,
      confidence: 0.80,
      informationBits: 3.0,
      rawData: analysis.mailer,
      sourceUrl: 'email-header-analysis',
    })
  }

  return {
    data: analysis,
    signals,
    raw: analysis.rawHeaders,
    url: 'email-header-analysis',
    collectedAt,
    warnings: [],
  }
}
