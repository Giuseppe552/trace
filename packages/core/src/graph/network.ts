/**
 * Network graph analysis for mapping operational infrastructure.
 *
 * Given seed identifiers (domains, emails, IPs), expands through shared
 * attributes and clusters related entities. Adapted from threadr's
 * spectral clustering — same normalized Laplacian, same Fiedler vector
 * for sub-group identification.
 *
 * Use case: attacker registers 5 domains to run a smear campaign.
 * 3 share a registrant email, 2 share nameservers, 4 share an IP.
 * The graph connects them all, Fiedler vector identifies the cluster.
 *
 * Reference: Fiedler, M. (1973). "Algebraic connectivity of graphs."
 * Reference: Meiklejohn et al. (2013). "A fistful of bitcoins."
 *   (graph clustering for entity resolution)
 */

/** A node in the attribution graph */
export interface GraphNode {
  id: string
  type: 'domain' | 'email' | 'ip' | 'nameserver' | 'registrant' | 'certificate' | 'person' | 'review_profile'
  label: string
  metadata?: Record<string, unknown>
}

/** An edge linking two nodes */
export interface GraphEdge {
  source: string
  target: string
  type: 'registered_by' | 'hosted_on' | 'uses_ns' | 'shares_cert' | 'same_registrant' | 'same_ip' | 'reviewed_by' | 'linked_to' | 'writing_match'
  weight: number  // 0-1, strength of association
  evidence?: string
}

/** The full attribution graph */
export interface AttributionGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

/** A cluster of related nodes */
export interface Cluster {
  id: number
  nodes: string[]
  /** density: edges_within / max_possible_edges */
  density: number
  /** central node (highest degree within cluster) */
  hub: string
}

/**
 * Build an adjacency matrix from the graph.
 * Returns the matrix and a mapping from node ID to index.
 */
export function adjacencyMatrix(graph: AttributionGraph): {
  matrix: number[][]
  nodeIndex: Map<string, number>
  indexNode: Map<number, string>
} {
  const nodeIndex = new Map<string, number>()
  const indexNode = new Map<number, string>()
  graph.nodes.forEach((n, i) => {
    nodeIndex.set(n.id, i)
    indexNode.set(i, n.id)
  })

  const n = graph.nodes.length
  const matrix: number[][] = Array.from({ length: n }, () => new Array(n).fill(0))

  for (const edge of graph.edges) {
    const i = nodeIndex.get(edge.source)
    const j = nodeIndex.get(edge.target)
    if (i !== undefined && j !== undefined) {
      matrix[i][j] = edge.weight
      matrix[j][i] = edge.weight // undirected
    }
  }

  return { matrix, nodeIndex, indexNode }
}

/**
 * Compute the degree of each node.
 */
export function nodeDegrees(graph: AttributionGraph): Map<string, number> {
  const degrees = new Map<string, number>()
  for (const node of graph.nodes) {
    degrees.set(node.id, 0)
  }
  for (const edge of graph.edges) {
    degrees.set(edge.source, (degrees.get(edge.source) ?? 0) + edge.weight)
    degrees.set(edge.target, (degrees.get(edge.target) ?? 0) + edge.weight)
  }
  return degrees
}

/**
 * Find connected components via BFS.
 *
 * Fast path before spectral methods — disconnected components
 * produce multiple zero eigenvalues and break power iteration.
 * (Learned from threadr: this edge case cost debugging time.)
 */
export function connectedComponents(graph: AttributionGraph): string[][] {
  const adj = new Map<string, Set<string>>()
  for (const node of graph.nodes) {
    adj.set(node.id, new Set())
  }
  for (const edge of graph.edges) {
    adj.get(edge.source)?.add(edge.target)
    adj.get(edge.target)?.add(edge.source)
  }

  const visited = new Set<string>()
  const components: string[][] = []

  for (const node of graph.nodes) {
    if (visited.has(node.id)) continue

    const component: string[] = []
    const queue = [node.id]
    visited.add(node.id)

    while (queue.length > 0) {
      const current = queue.shift()!
      component.push(current)
      for (const neighbor of adj.get(current) ?? []) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor)
          queue.push(neighbor)
        }
      }
    }

    components.push(component)
  }

  return components
}

/**
 * Normalized graph Laplacian: L = I - D^(-1/2) A D^(-1/2)
 *
 * Eigenvalues are in [0, 2]. The number of zero eigenvalues
 * equals the number of connected components. The Fiedler value
 * (second-smallest eigenvalue) measures algebraic connectivity.
 */
export function normalizedLaplacian(adjMatrix: number[][]): number[][] {
  const n = adjMatrix.length
  const L: number[][] = Array.from({ length: n }, () => new Array(n).fill(0))

  // degree of each node
  const deg: number[] = new Array(n).fill(0)
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      deg[i] += adjMatrix[i][j]
    }
  }

  // L = I - D^(-1/2) A D^(-1/2)
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      if (i === j) {
        L[i][j] = deg[i] > 0 ? 1 : 0
      } else if (adjMatrix[i][j] > 0 && deg[i] > 0 && deg[j] > 0) {
        L[i][j] = -adjMatrix[i][j] / Math.sqrt(deg[i] * deg[j])
      }
    }
  }

  return L
}

/**
 * Power iteration to find the smallest eigenvector of a matrix.
 *
 * Uses shift-and-invert: finds the largest eigenvector of (λI - L)
 * which corresponds to the smallest eigenvector of L.
 *
 * For the Fiedler vector: compute on the Laplacian, skip the
 * trivial (constant) eigenvector.
 */
export function powerIteration(
  matrix: number[][],
  maxIter = 1000,
  tol = 1e-8,
): { eigenvalue: number; eigenvector: number[] } {
  const n = matrix.length
  if (n === 0) return { eigenvalue: 0, eigenvector: [] }

  // start with random vector
  let v = Array.from({ length: n }, () => Math.random() - 0.5)
  let norm = Math.sqrt(v.reduce((s, x) => s + x * x, 0))
  v = v.map(x => x / norm)

  let eigenvalue = 0

  for (let iter = 0; iter < maxIter; iter++) {
    // matrix-vector multiply
    const Av = new Array(n).fill(0)
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        Av[i] += matrix[i][j] * v[j]
      }
    }

    // Rayleigh quotient
    eigenvalue = v.reduce((s, vi, i) => s + vi * Av[i], 0)

    // normalise
    norm = Math.sqrt(Av.reduce((s, x) => s + x * x, 0))
    if (norm < 1e-15) break

    const vNew = Av.map(x => x / norm)

    // convergence check
    const diff = vNew.reduce((s, x, i) => s + (x - v[i]) ** 2, 0)
    v = vNew
    if (diff < tol * tol) break
  }

  return { eigenvalue, eigenvector: v }
}

/**
 * Fiedler vector: the eigenvector corresponding to the second-smallest
 * eigenvalue of the normalized Laplacian.
 *
 * The sign of each component determines which partition the node
 * belongs to. Nodes with similar Fiedler values are in the same cluster.
 */
export function fiedlerVector(graph: AttributionGraph): {
  vector: Map<string, number>
  algebraicConnectivity: number
} | null {
  const components = connectedComponents(graph)
  if (components.length > 1) {
    // disconnected — Fiedler vector is only meaningful for connected graphs
    return null
  }

  const { matrix, indexNode } = adjacencyMatrix(graph)
  const L = normalizedLaplacian(matrix)
  const n = L.length
  if (n < 2) return null

  // shift to find second-smallest: use (2I - L) and find largest eigenvector
  // then deflate to remove the trivial constant eigenvector
  const shifted: number[][] = Array.from({ length: n }, (_, i) =>
    Array.from({ length: n }, (_, j) => (i === j ? 2 : 0) - L[i][j]),
  )

  // first eigenvector of shifted matrix (corresponds to smallest eigenvalue of L)
  const { eigenvector: v1 } = powerIteration(shifted)

  // deflate: A' = A - λ₁ v₁ v₁ᵀ
  const lambda1Approx = 2 // max eigenvalue of shifted ≈ 2 (for the constant vector)
  const deflated: number[][] = shifted.map((row, i) =>
    row.map((val, j) => val - lambda1Approx * v1[i] * v1[j]),
  )

  // second eigenvector
  const { eigenvalue: lambda2Shifted, eigenvector: fiedler } = powerIteration(deflated)
  const algebraicConnectivity = 2 - lambda2Shifted

  const vector = new Map<string, number>()
  fiedler.forEach((val, idx) => {
    const nodeId = indexNode.get(idx)
    if (nodeId) vector.set(nodeId, val)
  })

  return { vector, algebraicConnectivity }
}

/**
 * Partition a connected graph into two clusters using the Fiedler vector.
 * Nodes with positive Fiedler values go to cluster 0,
 * nodes with negative values go to cluster 1.
 */
export function spectralBipartition(graph: AttributionGraph): Cluster[] | null {
  const result = fiedlerVector(graph)
  if (!result) return null

  const degrees = nodeDegrees(graph)
  const cluster0: string[] = []
  const cluster1: string[] = []

  for (const [nodeId, val] of result.vector) {
    if (val >= 0) cluster0.push(nodeId)
    else cluster1.push(nodeId)
  }

  function clusterDensity(nodeIds: string[]): number {
    const nodeSet = new Set(nodeIds)
    let edgesWithin = 0
    for (const edge of graph.edges) {
      if (nodeSet.has(edge.source) && nodeSet.has(edge.target)) edgesWithin++
    }
    const maxEdges = (nodeIds.length * (nodeIds.length - 1)) / 2
    return maxEdges > 0 ? edgesWithin / maxEdges : 0
  }

  function findHub(nodeIds: string[]): string {
    let maxDeg = -1
    let hub = nodeIds[0]
    for (const id of nodeIds) {
      const d = degrees.get(id) ?? 0
      if (d > maxDeg) { maxDeg = d; hub = id }
    }
    return hub
  }

  const clusters: Cluster[] = []
  if (cluster0.length > 0) {
    clusters.push({ id: 0, nodes: cluster0, density: clusterDensity(cluster0), hub: findHub(cluster0) })
  }
  if (cluster1.length > 0) {
    clusters.push({ id: 1, nodes: cluster1, density: clusterDensity(cluster1), hub: findHub(cluster1) })
  }

  return clusters
}
