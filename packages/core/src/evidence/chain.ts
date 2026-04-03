/**
 * Evidence chain with cryptographic integrity.
 *
 * Every piece of evidence collected during an investigation is
 * logged with: timestamp, SHA-256 hash of content, source URL,
 * analyst identifier, and a chain hash linking to the previous entry.
 *
 * This follows the Berkeley Protocol on Digital Open Source
 * Investigations (OHCHR, 2020) requirements for chain of custody.
 *
 * The chain is append-only and tamper-evident — modifying any entry
 * breaks every subsequent chain hash. Same design as the VPE audit
 * chain in PDF Changer.
 */

/** A single evidence entry in the chain */
export interface EvidenceEntry {
  /** sequential index */
  seq: number
  /** ISO 8601 timestamp */
  timestamp: string
  /** SHA-256 hash of the evidence content */
  contentHash: string
  /** what type of evidence this is */
  type: 'screenshot' | 'html' | 'dns_record' | 'whois_record' | 'http_headers' | 'certificate' | 'review_data' | 'email_headers' | 'api_response' | 'archive_url' | 'stylometry_result' | 'other'
  /** source URL or identifier */
  source: string
  /** brief description of what this evidence shows */
  description: string
  /** which investigation layer produced this */
  layer: string
  /** hash of the previous entry (genesis = all zeros) */
  prevHash: string
  /** hash of this entire entry (including prevHash) */
  entryHash: string
}

/** The full evidence chain */
export interface EvidenceChain {
  /** investigation identifier */
  investigationId: string
  /** when the investigation started */
  startedAt: string
  /** analyst identifier */
  analyst: string
  /** all entries in order */
  entries: EvidenceEntry[]
}

const GENESIS_HASH = '0'.repeat(64)

/**
 * SHA-256 hash of a string. Uses Web Crypto API.
 * Falls back to Node.js crypto if Web Crypto unavailable.
 */
export async function sha256(input: string): Promise<string> {
  if (typeof globalThis.crypto?.subtle?.digest === 'function') {
    const buf = new TextEncoder().encode(input)
    const hash = await globalThis.crypto.subtle.digest('SHA-256', buf)
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  }
  // Node.js fallback
  const { createHash } = await import('node:crypto')
  return createHash('sha256').update(input).digest('hex')
}

/**
 * Create a new evidence chain for an investigation.
 */
export function createChain(
  investigationId: string,
  analyst: string,
): EvidenceChain {
  return {
    investigationId,
    startedAt: new Date().toISOString(),
    analyst,
    entries: [],
  }
}

/**
 * Append an evidence entry to the chain.
 *
 * The entry hash covers: seq, timestamp, contentHash, type, source,
 * description, layer, and prevHash. Changing any field breaks the chain.
 */
export async function appendEvidence(
  chain: EvidenceChain,
  evidence: {
    content: string | Uint8Array
    type: EvidenceEntry['type']
    source: string
    description: string
    layer: string
  },
): Promise<EvidenceEntry> {
  const seq = chain.entries.length
  const timestamp = new Date().toISOString()
  const prevHash = seq === 0
    ? GENESIS_HASH
    : chain.entries[seq - 1].entryHash

  // hash the actual content
  const contentStr = typeof evidence.content === 'string'
    ? evidence.content
    : Array.from(evidence.content).map(b => b.toString(16).padStart(2, '0')).join('')
  const contentHash = await sha256(contentStr)

  // hash the entire entry (including prevHash for chain integrity)
  const entryPayload = JSON.stringify({
    seq,
    timestamp,
    contentHash,
    type: evidence.type,
    source: evidence.source,
    description: evidence.description,
    layer: evidence.layer,
    prevHash,
  })
  const entryHash = await sha256(entryPayload)

  const entry: EvidenceEntry = {
    seq,
    timestamp,
    contentHash,
    type: evidence.type,
    source: evidence.source,
    description: evidence.description,
    layer: evidence.layer,
    prevHash,
    entryHash,
  }

  chain.entries.push(entry)
  return entry
}

/**
 * Verify the integrity of an evidence chain.
 *
 * Checks:
 * 1. Sequential numbering
 * 2. Each prevHash matches the previous entry's entryHash
 * 3. Genesis entry has all-zero prevHash
 * 4. Each entryHash matches the recomputed hash
 *
 * Returns the index of the first broken entry, or -1 if intact.
 */
export async function verifyChain(chain: EvidenceChain): Promise<{
  intact: boolean
  brokenAt: number
  totalEntries: number
  error?: string
}> {
  for (let i = 0; i < chain.entries.length; i++) {
    const entry = chain.entries[i]

    // check seq
    if (entry.seq !== i) {
      return { intact: false, brokenAt: i, totalEntries: chain.entries.length, error: `seq mismatch: expected ${i}, got ${entry.seq}` }
    }

    // check prevHash
    const expectedPrev = i === 0 ? GENESIS_HASH : chain.entries[i - 1].entryHash
    if (entry.prevHash !== expectedPrev) {
      return { intact: false, brokenAt: i, totalEntries: chain.entries.length, error: `prevHash mismatch at entry ${i}` }
    }

    // recompute entryHash
    const payload = JSON.stringify({
      seq: entry.seq,
      timestamp: entry.timestamp,
      contentHash: entry.contentHash,
      type: entry.type,
      source: entry.source,
      description: entry.description,
      layer: entry.layer,
      prevHash: entry.prevHash,
    })
    const recomputed = await sha256(payload)
    if (recomputed !== entry.entryHash) {
      return { intact: false, brokenAt: i, totalEntries: chain.entries.length, error: `entryHash tampered at entry ${i}` }
    }
  }

  return { intact: true, brokenAt: -1, totalEntries: chain.entries.length }
}

/**
 * Export chain as a JSON report for legal/forensic use.
 */
export function exportReport(chain: EvidenceChain): string {
  return JSON.stringify({
    _format: 'trace-evidence-chain-v1',
    _protocol: 'Berkeley Protocol on Digital Open Source Investigations (OHCHR, 2020)',
    investigation: chain.investigationId,
    analyst: chain.analyst,
    started: chain.startedAt,
    exported: new Date().toISOString(),
    totalEntries: chain.entries.length,
    entries: chain.entries,
  }, null, 2)
}
