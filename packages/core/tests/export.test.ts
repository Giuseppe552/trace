import { describe, it, expect } from 'vitest'
import {
  toDot,
  toD3Json,
  buildGraphFromSignals,
} from '../src/graph/export.js'
import type { AttributionGraph } from '../src/graph/network.js'

const SAMPLE_GRAPH: AttributionGraph = {
  nodes: [
    { id: 'example.com', type: 'domain', label: 'example.com' },
    { id: 'admin@example.com', type: 'email', label: 'admin@example.com' },
    { id: '1.2.3.4', type: 'ip', label: '1.2.3.4' },
    { id: 'ns1.cloudflare.com', type: 'nameserver', label: 'ns1.cloudflare.com' },
  ],
  edges: [
    { source: 'example.com', target: 'admin@example.com', type: 'registered_by', weight: 1 },
    { source: 'example.com', target: '1.2.3.4', type: 'hosted_on', weight: 0.8 },
    { source: 'example.com', target: 'ns1.cloudflare.com', type: 'uses_ns', weight: 0.6 },
  ],
}

describe('toDot', () => {
  it('produces valid DOT output', () => {
    const dot = toDot(SAMPLE_GRAPH)
    expect(dot).toContain('digraph trace {')
    expect(dot).toContain('}')
  })

  it('includes all nodes', () => {
    const dot = toDot(SAMPLE_GRAPH)
    expect(dot).toContain('example.com')
    expect(dot).toContain('admin@example.com')
    expect(dot).toContain('1.2.3.4')
  })

  it('includes all edges', () => {
    const dot = toDot(SAMPLE_GRAPH)
    expect(dot).toContain('example.com" -> "admin@example.com"')
    expect(dot).toContain('example.com" -> "1.2.3.4"')
  })

  it('uses correct colors for node types', () => {
    const dot = toDot(SAMPLE_GRAPH)
    expect(dot).toContain('#ff6b35') // domain = orange
    expect(dot).toContain('#3b82f6') // email = blue
    expect(dot).toContain('#a78bfa') // ip = violet
  })

  it('uses correct edge styles', () => {
    const dot = toDot(SAMPLE_GRAPH)
    expect(dot).toContain('style=solid') // registered_by
    expect(dot).toContain('style=dashed') // hosted_on
    expect(dot).toContain('style=dotted') // uses_ns
  })

  it('respects custom title', () => {
    const dot = toDot(SAMPLE_GRAPH, { title: 'my investigation' })
    expect(dot).toContain('my investigation')
  })

  it('handles empty graph', () => {
    const dot = toDot({ nodes: [], edges: [] })
    expect(dot).toContain('digraph trace {')
    expect(dot).toContain('}')
  })

  it('escapes quotes in labels', () => {
    const graph: AttributionGraph = {
      nodes: [{ id: 'test', type: 'domain', label: 'has "quotes" here' }],
      edges: [],
    }
    const dot = toDot(graph)
    expect(dot).toContain('\\"quotes\\"')
  })
})

describe('toD3Json', () => {
  it('produces valid JSON', () => {
    const json = toD3Json(SAMPLE_GRAPH)
    const parsed = JSON.parse(json)
    expect(parsed.nodes).toBeDefined()
    expect(parsed.links).toBeDefined()
  })

  it('includes all nodes with colors', () => {
    const parsed = JSON.parse(toD3Json(SAMPLE_GRAPH))
    expect(parsed.nodes.length).toBe(4)
    expect(parsed.nodes[0].color).toBeDefined()
  })

  it('includes all links with weights', () => {
    const parsed = JSON.parse(toD3Json(SAMPLE_GRAPH))
    expect(parsed.links.length).toBe(3)
    expect(parsed.links[0].weight).toBeDefined()
  })
})

describe('buildGraphFromSignals', () => {
  it('creates domain node for target', () => {
    const graph = buildGraphFromSignals('target.com', [])
    expect(graph.nodes.length).toBe(1)
    expect(graph.nodes[0].id).toBe('target.com')
    expect(graph.nodes[0].type).toBe('domain')
  })

  it('creates email node from whois signal', () => {
    const graph = buildGraphFromSignals('target.com', [
      { source: 'whois', observation: 'registrant email: admin@target.com', rawData: 'admin@target.com' },
    ])
    expect(graph.nodes.find(n => n.id === 'admin@target.com')).toBeDefined()
    expect(graph.edges.find(e => e.type === 'registered_by')).toBeDefined()
  })

  it('creates IP node from dns signal', () => {
    const graph = buildGraphFromSignals('target.com', [
      { source: 'dns', observation: 'hosted on: 1.2.3.4', rawData: '1.2.3.4' },
    ])
    expect(graph.nodes.find(n => n.id === '1.2.3.4')).toBeDefined()
    expect(graph.edges.find(e => e.type === 'hosted_on')).toBeDefined()
  })

  it('creates related domain nodes from CT signal', () => {
    const graph = buildGraphFromSignals('target.com', [
      { source: 'ct', observation: '2 related domains found via shared certificates', rawData: 'related1.com, related2.com' },
    ])
    expect(graph.nodes.find(n => n.id === 'related1.com')).toBeDefined()
    expect(graph.nodes.find(n => n.id === 'related2.com')).toBeDefined()
  })

  it('no duplicate nodes', () => {
    const graph = buildGraphFromSignals('target.com', [
      { source: 'whois', observation: 'nameservers: ns1.example.com, ns2.example.com', rawData: 'ns1.example.com, ns2.example.com' },
      { source: 'dns', observation: 'nameservers: ns1.example.com, ns2.example.com', rawData: 'ns1.example.com, ns2.example.com' },
    ])
    const ns1Nodes = graph.nodes.filter(n => n.id === 'ns1.example.com')
    expect(ns1Nodes.length).toBe(1)
  })
})
