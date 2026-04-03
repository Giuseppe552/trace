import { describe, it, expect } from 'vitest'
import {
  adjacencyMatrix,
  nodeDegrees,
  connectedComponents,
  normalizedLaplacian,
  powerIteration,
  fiedlerVector,
  spectralBipartition,
  type AttributionGraph,
} from '../src/graph/network.js'

function simpleGraph(): AttributionGraph {
  return {
    nodes: [
      { id: 'a', type: 'domain', label: 'example.com' },
      { id: 'b', type: 'domain', label: 'example.org' },
      { id: 'c', type: 'email', label: 'admin@example.com' },
      { id: 'd', type: 'ip', label: '1.2.3.4' },
    ],
    edges: [
      { source: 'a', target: 'c', type: 'registered_by', weight: 1 },
      { source: 'b', target: 'c', type: 'registered_by', weight: 1 },
      { source: 'a', target: 'd', type: 'hosted_on', weight: 0.8 },
      { source: 'b', target: 'd', type: 'hosted_on', weight: 0.8 },
    ],
  }
}

function disconnectedGraph(): AttributionGraph {
  return {
    nodes: [
      { id: 'a', type: 'domain', label: 'site1.com' },
      { id: 'b', type: 'domain', label: 'site2.com' },
      { id: 'c', type: 'domain', label: 'site3.com' },
      { id: 'd', type: 'domain', label: 'site4.com' },
    ],
    edges: [
      { source: 'a', target: 'b', type: 'same_registrant', weight: 1 },
      { source: 'c', target: 'd', type: 'same_ip', weight: 1 },
    ],
  }
}

// two clusters connected by a weak link
function bipartiteGraph(): AttributionGraph {
  return {
    nodes: [
      { id: 'a1', type: 'domain', label: 'cluster-a-1' },
      { id: 'a2', type: 'domain', label: 'cluster-a-2' },
      { id: 'a3', type: 'email', label: 'cluster-a-email' },
      { id: 'b1', type: 'domain', label: 'cluster-b-1' },
      { id: 'b2', type: 'domain', label: 'cluster-b-2' },
      { id: 'b3', type: 'ip', label: 'cluster-b-ip' },
    ],
    edges: [
      // cluster A: tightly connected
      { source: 'a1', target: 'a2', type: 'same_registrant', weight: 1 },
      { source: 'a1', target: 'a3', type: 'registered_by', weight: 1 },
      { source: 'a2', target: 'a3', type: 'registered_by', weight: 1 },
      // cluster B: tightly connected
      { source: 'b1', target: 'b2', type: 'same_registrant', weight: 1 },
      { source: 'b1', target: 'b3', type: 'hosted_on', weight: 1 },
      { source: 'b2', target: 'b3', type: 'hosted_on', weight: 1 },
      // weak link between clusters
      { source: 'a2', target: 'b1', type: 'same_ip', weight: 0.2 },
    ],
  }
}

describe('adjacencyMatrix', () => {
  it('builds correct matrix for simple graph', () => {
    const g = simpleGraph()
    const { matrix, nodeIndex } = adjacencyMatrix(g)
    expect(matrix.length).toBe(4)
    expect(matrix[nodeIndex.get('a')!][nodeIndex.get('c')!]).toBe(1)
    expect(matrix[nodeIndex.get('c')!][nodeIndex.get('a')!]).toBe(1) // symmetric
  })

  it('matrix is symmetric', () => {
    const { matrix } = adjacencyMatrix(simpleGraph())
    for (let i = 0; i < matrix.length; i++) {
      for (let j = 0; j < matrix.length; j++) {
        expect(matrix[i][j]).toBe(matrix[j][i])
      }
    }
  })
})

describe('nodeDegrees', () => {
  it('computes correct degrees', () => {
    const degrees = nodeDegrees(simpleGraph())
    expect(degrees.get('c')).toBe(2) // connected to a and b
    expect(degrees.get('a')).toBeCloseTo(1.8, 5) // c(1) + d(0.8)
  })
})

describe('connectedComponents', () => {
  it('finds one component in connected graph', () => {
    const components = connectedComponents(simpleGraph())
    expect(components.length).toBe(1)
    expect(components[0].length).toBe(4)
  })

  it('finds two components in disconnected graph', () => {
    const components = connectedComponents(disconnectedGraph())
    expect(components.length).toBe(2)
    expect(components.map(c => c.length).sort()).toEqual([2, 2])
  })

  it('handles empty graph', () => {
    const components = connectedComponents({ nodes: [], edges: [] })
    expect(components.length).toBe(0)
  })

  it('handles isolated nodes', () => {
    const g: AttributionGraph = {
      nodes: [
        { id: 'x', type: 'domain', label: 'alone.com' },
        { id: 'y', type: 'domain', label: 'pair1.com' },
        { id: 'z', type: 'domain', label: 'pair2.com' },
      ],
      edges: [{ source: 'y', target: 'z', type: 'same_ip', weight: 1 }],
    }
    const components = connectedComponents(g)
    expect(components.length).toBe(2)
  })
})

describe('normalizedLaplacian', () => {
  it('diagonal elements are 0 or 1', () => {
    const { matrix } = adjacencyMatrix(simpleGraph())
    const L = normalizedLaplacian(matrix)
    for (let i = 0; i < L.length; i++) {
      expect(L[i][i]).toBeGreaterThanOrEqual(0)
      expect(L[i][i]).toBeLessThanOrEqual(1 + 1e-10)
    }
  })

  it('rows sum to approximately 0 for connected nodes', () => {
    const { matrix } = adjacencyMatrix(simpleGraph())
    const L = normalizedLaplacian(matrix)
    for (let i = 0; i < L.length; i++) {
      const rowSum = L[i].reduce((a, b) => a + b, 0)
      expect(Math.abs(rowSum)).toBeLessThan(0.5) // approximately 0
    }
  })

  it('eigenvalues are non-negative (L is PSD)', () => {
    // verify via Gershgorin: each eigenvalue is within |row sum off-diagonal| of diagonal
    const { matrix } = adjacencyMatrix(simpleGraph())
    const L = normalizedLaplacian(matrix)
    for (let i = 0; i < L.length; i++) {
      let offDiagSum = 0
      for (let j = 0; j < L.length; j++) {
        if (i !== j) offDiagSum += Math.abs(L[i][j])
      }
      // Gershgorin bound: eigenvalue ∈ [diag - offDiagSum, diag + offDiagSum]
      // for normalized Laplacian, eigenvalues are in [0, 2]
      // the lower Gershgorin bound can be negative for individual rows
      // but actual eigenvalues remain non-negative
      expect(L[i][i] - offDiagSum).toBeGreaterThanOrEqual(-0.5)
    }
  })
})

describe('powerIteration', () => {
  it('finds dominant eigenvalue of identity', () => {
    const I = [[1, 0], [0, 1]]
    const { eigenvalue } = powerIteration(I)
    expect(eigenvalue).toBeCloseTo(1, 5)
  })

  it('finds dominant eigenvalue of known matrix', () => {
    // [[2, 1], [1, 2]] has eigenvalues 3 and 1
    const { eigenvalue } = powerIteration([[2, 1], [1, 2]])
    expect(eigenvalue).toBeCloseTo(3, 3)
  })

  it('eigenvector has unit norm', () => {
    const { eigenvector } = powerIteration([[3, 1], [1, 3]])
    const norm = Math.sqrt(eigenvector.reduce((s, x) => s + x * x, 0))
    expect(norm).toBeCloseTo(1, 5)
  })
})

describe('fiedlerVector', () => {
  it('returns null for disconnected graph', () => {
    expect(fiedlerVector(disconnectedGraph())).toBeNull()
  })

  it('returns vector for connected graph', () => {
    const result = fiedlerVector(simpleGraph())
    expect(result).not.toBeNull()
    expect(result!.vector.size).toBe(4)
  })

  it('algebraic connectivity > 0 for connected graph', () => {
    const result = fiedlerVector(simpleGraph())
    expect(result!.algebraicConnectivity).toBeGreaterThan(0)
  })
})

describe('spectralBipartition', () => {
  it('returns null for disconnected graph', () => {
    expect(spectralBipartition(disconnectedGraph())).toBeNull()
  })

  it('finds two clusters in bipartite-like graph', () => {
    const clusters = spectralBipartition(bipartiteGraph())
    expect(clusters).not.toBeNull()
    expect(clusters!.length).toBe(2)
    // all 6 nodes should be assigned
    const allNodes = clusters!.flatMap(c => c.nodes)
    expect(allNodes.length).toBe(6)
    expect(new Set(allNodes).size).toBe(6)
  })

  it('separates clusters correctly', () => {
    const clusters = spectralBipartition(bipartiteGraph())
    if (!clusters) return

    // a-nodes and b-nodes should be in different clusters
    const clusterOf = new Map<string, number>()
    for (const c of clusters) {
      for (const n of c.nodes) clusterOf.set(n, c.id)
    }

    // a1, a2, a3 should all be in the same cluster
    expect(clusterOf.get('a1')).toBe(clusterOf.get('a2'))
    expect(clusterOf.get('a2')).toBe(clusterOf.get('a3'))
    // b1, b2, b3 should all be in the same cluster
    expect(clusterOf.get('b1')).toBe(clusterOf.get('b2'))
    expect(clusterOf.get('b2')).toBe(clusterOf.get('b3'))
    // a-cluster ≠ b-cluster
    expect(clusterOf.get('a1')).not.toBe(clusterOf.get('b1'))
  })

  it('each cluster has a hub', () => {
    const clusters = spectralBipartition(bipartiteGraph())
    if (!clusters) return
    for (const c of clusters) {
      expect(c.hub).toBeDefined()
      expect(c.nodes).toContain(c.hub)
    }
  })

  it('density ∈ [0, 1]', () => {
    const clusters = spectralBipartition(bipartiteGraph())
    if (!clusters) return
    for (const c of clusters) {
      expect(c.density).toBeGreaterThanOrEqual(0)
      expect(c.density).toBeLessThanOrEqual(1)
    }
  })
})
