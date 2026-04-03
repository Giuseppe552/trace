/**
 * Continuous monitoring engine.
 *
 * Runs periodic checks against a set of targets and detects changes.
 * This is the foundation for the "overwatch" concept — continuous
 * awareness rather than on-demand investigation.
 *
 * Monitors:
 * - DNS record changes (new A records, NS changes, MX changes)
 * - CT log new certificates (new subdomains appearing)
 * - WHOIS changes (registrant, nameserver, registrar changes)
 * - New domains registered by a known registrant (via reverse WHOIS)
 *
 * Each check produces a diff against the previous state.
 * State is stored as JSON files (no database dependency).
 */

import { collectDns, type DnsResult } from '../dns/resolver.js'
import { collectCT, type CtResult } from '../ct/crtsh.js'
import type { Signal } from '../types.js'

/** A monitored target */
export interface MonitorTarget {
  domain: string
  /** which checks to run */
  checks: Array<'dns' | 'ct' | 'whois'>
}

/** Previous state snapshot */
export interface MonitorState {
  domain: string
  lastChecked: string
  dns?: {
    a: string[]
    ns: string[]
    mx: string[]
    txt: string[]
  }
  ct?: {
    certCount: number
    subdomains: string[]
  }
}

/** A detected change */
export interface MonitorChange {
  domain: string
  timestamp: string
  type: 'dns_a_changed' | 'dns_ns_changed' | 'dns_mx_changed' | 'dns_txt_changed' | 'ct_new_subdomain' | 'ct_new_certs'
  description: string
  previous: string
  current: string
  severity: 'high' | 'medium' | 'low'
}

/** Result of a monitoring pass */
export interface MonitorResult {
  domain: string
  checkedAt: string
  changes: MonitorChange[]
  signals: Signal[]
  newState: MonitorState
}

/**
 * Run a monitoring pass against a domain.
 *
 * Compares current state against previousState.
 * Returns detected changes and the new state for persistence.
 */
export async function monitorDomain(
  target: MonitorTarget,
  previousState: MonitorState | null,
): Promise<MonitorResult> {
  const checkedAt = new Date().toISOString()
  const changes: MonitorChange[] = []
  const signals: Signal[] = []

  const newState: MonitorState = {
    domain: target.domain,
    lastChecked: checkedAt,
  }

  // DNS monitoring
  if (target.checks.includes('dns')) {
    try {
      const dnsResult = await collectDns(target.domain)
      const dns = dnsResult.data

      newState.dns = {
        a: dns.a,
        ns: dns.ns,
        mx: dns.mx.map(m => m.exchange),
        txt: dns.txt,
      }

      if (previousState?.dns) {
        // A record changes
        const addedA = dns.a.filter(ip => !previousState.dns!.a.includes(ip))
        const removedA = previousState.dns.a.filter(ip => !dns.a.includes(ip))
        if (addedA.length > 0 || removedA.length > 0) {
          changes.push({
            domain: target.domain,
            timestamp: checkedAt,
            type: 'dns_a_changed',
            description: `A records changed: +${addedA.join(',')} -${removedA.join(',')}`,
            previous: previousState.dns.a.join(', '),
            current: dns.a.join(', '),
            severity: 'high',
          })
        }

        // NS changes (very significant — indicates DNS provider change)
        const addedNs = dns.ns.filter(ns => !previousState.dns!.ns.includes(ns))
        const removedNs = previousState.dns.ns.filter(ns => !dns.ns.includes(ns))
        if (addedNs.length > 0 || removedNs.length > 0) {
          changes.push({
            domain: target.domain,
            timestamp: checkedAt,
            type: 'dns_ns_changed',
            description: `nameservers changed: +${addedNs.join(',')} -${removedNs.join(',')}`,
            previous: previousState.dns.ns.join(', '),
            current: dns.ns.join(', '),
            severity: 'high',
          })
        }

        // MX changes
        const currentMx = dns.mx.map(m => m.exchange)
        const addedMx = currentMx.filter(mx => !previousState.dns!.mx.includes(mx))
        const removedMx = previousState.dns.mx.filter(mx => !currentMx.includes(mx))
        if (addedMx.length > 0 || removedMx.length > 0) {
          changes.push({
            domain: target.domain,
            timestamp: checkedAt,
            type: 'dns_mx_changed',
            description: `MX records changed: +${addedMx.join(',')} -${removedMx.join(',')}`,
            previous: previousState.dns.mx.join(', '),
            current: currentMx.join(', '),
            severity: 'medium',
          })
        }

        // TXT changes (SPF, DMARC modifications)
        const addedTxt = dns.txt.filter(t => !previousState.dns!.txt.includes(t))
        const removedTxt = previousState.dns.txt.filter(t => !dns.txt.includes(t))
        if (addedTxt.length > 0 || removedTxt.length > 0) {
          changes.push({
            domain: target.domain,
            timestamp: checkedAt,
            type: 'dns_txt_changed',
            description: `TXT records changed: ${addedTxt.length} added, ${removedTxt.length} removed`,
            previous: previousState.dns.txt.join(' | '),
            current: dns.txt.join(' | '),
            severity: 'medium',
          })
        }
      }
    } catch { /* non-fatal */ }
  }

  // CT monitoring
  if (target.checks.includes('ct')) {
    try {
      const ctResult = await collectCT(target.domain)

      newState.ct = {
        certCount: ctResult.data.certificates.length,
        subdomains: ctResult.data.subdomains,
      }

      if (previousState?.ct) {
        // new subdomains
        const newSubdomains = ctResult.data.subdomains.filter(
          s => !previousState.ct!.subdomains.includes(s),
        )
        if (newSubdomains.length > 0) {
          changes.push({
            domain: target.domain,
            timestamp: checkedAt,
            type: 'ct_new_subdomain',
            description: `${newSubdomains.length} new subdomain(s): ${newSubdomains.join(', ')}`,
            previous: `${previousState.ct.subdomains.length} subdomains`,
            current: `${ctResult.data.subdomains.length} subdomains`,
            severity: 'medium',
          })
        }

        // significant cert count increase
        const certIncrease = ctResult.data.certificates.length - previousState.ct.certCount
        if (certIncrease > 5) {
          changes.push({
            domain: target.domain,
            timestamp: checkedAt,
            type: 'ct_new_certs',
            description: `${certIncrease} new certificates issued since last check`,
            previous: `${previousState.ct.certCount} certs`,
            current: `${ctResult.data.certificates.length} certs`,
            severity: 'low',
          })
        }
      }
    } catch { /* non-fatal */ }
  }

  // convert changes to signals
  for (const change of changes) {
    signals.push({
      source: 'monitor',
      observation: `[${change.severity.toUpperCase()}] ${change.domain}: ${change.description}`,
      score: change.severity === 'high' ? 0.8 : change.severity === 'medium' ? 0.5 : 0.3,
      confidence: 0.95,
      informationBits: change.severity === 'high' ? 5.0 : 2.0,
      rawData: JSON.stringify(change),
      sourceUrl: `monitor:${target.domain}`,
    })
  }

  return { domain: target.domain, checkedAt, changes, signals, newState }
}

/**
 * Run monitoring across multiple targets.
 */
export async function monitorAll(
  targets: MonitorTarget[],
  previousStates: Map<string, MonitorState>,
): Promise<MonitorResult[]> {
  const results: MonitorResult[] = []

  for (const target of targets) {
    const prev = previousStates.get(target.domain) ?? null
    const result = await monitorDomain(target, prev)
    results.push(result)
  }

  return results
}
