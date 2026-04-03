/**
 * Graph export in DOT (Graphviz) and JSON formats.
 *
 * DOT output can be rendered with:
 *   dot -Tsvg graph.dot -o graph.svg
 *   dot -Tpng graph.dot -o graph.png
 *
 * Or in the browser with d3-graphviz or viz.js.
 *
 * JSON output follows the d3 force-directed graph format
 * for direct rendering in the portfolio web demo.
 */

import type { AttributionGraph, Cluster } from './network.js'

/** Node type → DOT color mapping */
const TYPE_COLORS: Record<string, string> = {
  domain: '#ff6b35',      // orange
  email: '#3b82f6',       // blue
  ip: '#a78bfa',          // violet
  nameserver: '#707e9a',  // grey
  registrant: '#f59e0b',  // amber
  certificate: '#10b981', // green
  person: '#ef4444',      // red
  review_profile: '#ec4899', // pink
}

/** Edge type → DOT style mapping */
const EDGE_STYLES: Record<string, string> = {
  registered_by: 'solid',
  hosted_on: 'dashed',
  uses_ns: 'dotted',
  shares_cert: 'solid',
  same_registrant: 'bold',
  same_ip: 'bold',
  reviewed_by: 'dashed',
  linked_to: 'solid',
  writing_match: 'dashed',
}

/**
 * Export attribution graph as DOT (Graphviz) format.
 */
export function toDot(
  graph: AttributionGraph,
  options: {
    title?: string
    clusters?: Cluster[]
    rankdir?: 'LR' | 'TB' | 'BT' | 'RL'
  } = {},
): string {
  const { title = 'trace attribution graph', rankdir = 'LR', clusters } = options
  const lines: string[] = []

  lines.push(`digraph trace {`)
  lines.push(`  label="${escDot(title)}";`)
  lines.push(`  labelloc="t";`)
  lines.push(`  fontname="Helvetica";`)
  lines.push(`  fontsize=14;`)
  lines.push(`  rankdir=${rankdir};`)
  lines.push(`  bgcolor="#0c1017";`)
  lines.push(`  node [fontname="Helvetica" fontsize=10 style=filled fontcolor=white];`)
  lines.push(`  edge [fontname="Helvetica" fontsize=8 fontcolor="#8b92a5"];`)
  lines.push('')

  // cluster subgraphs if provided
  if (clusters && clusters.length > 0) {
    for (const cluster of clusters) {
      lines.push(`  subgraph cluster_${cluster.id} {`)
      lines.push(`    label="cluster ${cluster.id} (density: ${cluster.density.toFixed(2)})";`)
      lines.push(`    style=dashed;`)
      lines.push(`    color="#707e9a";`)
      lines.push(`    fontcolor="#8b92a5";`)
      for (const nodeId of cluster.nodes) {
        lines.push(`    "${escDot(nodeId)}";`)
      }
      lines.push(`  }`)
      lines.push('')
    }
  }

  // nodes
  for (const node of graph.nodes) {
    const color = TYPE_COLORS[node.type] ?? '#707e9a'
    const shape = node.type === 'person' ? 'ellipse' : node.type === 'domain' ? 'box' : 'ellipse'
    lines.push(`  "${escDot(node.id)}" [label="${escDot(node.label)}" fillcolor="${color}" shape=${shape}];`)
  }
  lines.push('')

  // edges
  for (const edge of graph.edges) {
    const style = EDGE_STYLES[edge.type] ?? 'solid'
    const penwidth = Math.max(1, edge.weight * 3)
    const label = edge.evidence ? ` label="${escDot(edge.evidence)}"` : ''
    lines.push(`  "${escDot(edge.source)}" -> "${escDot(edge.target)}" [style=${style} penwidth=${penwidth.toFixed(1)} color="#707e9a"${label}];`)
  }

  lines.push('}')
  return lines.join('\n')
}

/**
 * Export as JSON for d3 force-directed graph rendering.
 */
export function toD3Json(graph: AttributionGraph): string {
  return JSON.stringify({
    nodes: graph.nodes.map(n => ({
      id: n.id,
      label: n.label,
      type: n.type,
      color: TYPE_COLORS[n.type] ?? '#707e9a',
      metadata: n.metadata,
    })),
    links: graph.edges.map(e => ({
      source: e.source,
      target: e.target,
      type: e.type,
      weight: e.weight,
      evidence: e.evidence,
    })),
  }, null, 2)
}

/**
 * Build an AttributionGraph from investigation signals.
 *
 * Converts flat signal data into nodes and edges for visualization.
 */
export function buildGraphFromSignals(
  targetDomain: string,
  signals: Array<{
    source: string
    observation: string
    rawData: string
  }>,
): AttributionGraph {
  const nodes = new Map<string, AttributionGraph['nodes'][0]>()
  const edges: AttributionGraph['edges'] = []

  // target domain is always a node
  nodes.set(targetDomain, { id: targetDomain, type: 'domain', label: targetDomain })

  for (const signal of signals) {
    if (signal.source === 'whois' || signal.source === 'whois_reverse') {
      if (signal.observation.includes('registrant email:')) {
        const email = signal.rawData
        nodes.set(email, { id: email, type: 'email', label: email })
        edges.push({ source: targetDomain, target: email, type: 'registered_by', weight: 1 })
      }
      if (signal.observation.includes('registrant name:') || signal.observation.includes('registrant organization:')) {
        const name = signal.rawData
        nodes.set(name, { id: name, type: 'registrant', label: name })
        edges.push({ source: targetDomain, target: name, type: 'registered_by', weight: 0.9 })
      }
      if (signal.observation.includes('nameservers:')) {
        for (const ns of signal.rawData.split(', ')) {
          nodes.set(ns, { id: ns, type: 'nameserver', label: ns })
          edges.push({ source: targetDomain, target: ns, type: 'uses_ns', weight: 0.6 })
        }
      }
    }

    if (signal.source === 'dns') {
      if (signal.observation.includes('hosted on:')) {
        for (const ip of signal.rawData.split(', ')) {
          nodes.set(ip, { id: ip, type: 'ip', label: ip })
          edges.push({ source: targetDomain, target: ip, type: 'hosted_on', weight: 0.8 })
        }
      }
    }

    if (signal.source === 'ct') {
      if (signal.observation.includes('related domains')) {
        for (const domain of signal.rawData.split(', ').slice(0, 10)) {
          if (domain && domain !== targetDomain) {
            nodes.set(domain, { id: domain, type: 'domain', label: domain })
            edges.push({ source: targetDomain, target: domain, type: 'shares_cert', weight: 0.7 })
          }
        }
      }
    }

    if (signal.source === 'correlation') {
      if (signal.observation.includes('share')) {
        // extract domains from the observation
        const domainsMatch = signal.observation.match(/^(.+?) share/)
        if (domainsMatch) {
          const doms = domainsMatch[1].split(' + ')
          for (let i = 1; i < doms.length; i++) {
            const d = doms[i].trim()
            if (!nodes.has(d)) nodes.set(d, { id: d, type: 'domain', label: d })
            edges.push({ source: doms[0].trim(), target: d, type: 'linked_to', weight: 0.9 })
          }
        }
      }
    }
  }

  return { nodes: [...nodes.values()], edges }
}

function escDot(s: string): string {
  return s.replace(/"/g, '\\"').replace(/\n/g, '\\n')
}
