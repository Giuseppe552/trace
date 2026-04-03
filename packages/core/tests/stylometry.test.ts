import { describe, it, expect } from 'vitest'
import {
  extractFeatures,
  featureVector,
  cosineSimilarity,
  compareWriteprints,
} from '../src/stylometry/writeprint.js'

const SAMPLE_A = `I scanned 15 immigration agencies for basic security headers. 14 scored F. The headers were perfect on one — Vercel defaults handle most of it. The actual problems were zero SPF, no DMARC, and Hotjar recording every form interaction. The headers gave them an A while their clients' passport copies were being captured by a session recording tool. That's when the tool stopped being a header checklist and started thinking about what actually matters. Seven scanners now: TLS, headers, DNS, exposed paths, third-party tracking, forms, and cookies.`

const SAMPLE_A_VARIANT = `I checked 12 law firms for basic security configuration. 11 scored poorly. The TLS was fine on most — cloud defaults handle it. The real issues were missing SPF, no DMARC enforcement, and FullStory recording every client interaction. The scores looked clean while case files were being captured by session replay tools. That's when the scanner evolved from a header check into something that looks at what genuinely matters. Six modules now: TLS, headers, email auth, exposed files, tracking scripts, and cookie flags.`

const SAMPLE_B = `Take the sourdough out of the fridge about two hours before you want to use it. Don't rush it. The dough needs to come to room temperature slowly or the crumb structure falls apart. I've tried every shortcut. They all produce the same flat, dense result. Two hours. Set a timer if you need to. Meanwhile, preheat your oven to 250 with the dutch oven inside. The thermal mass matters more than the temperature.`

describe('extractFeatures', () => {
  it('extracts wordCount', () => {
    const f = extractFeatures(SAMPLE_A)
    expect(f.wordCount).toBeGreaterThan(50)
  })

  it('avgWordLength is reasonable', () => {
    const f = extractFeatures(SAMPLE_A)
    expect(f.avgWordLength).toBeGreaterThan(3)
    expect(f.avgWordLength).toBeLessThan(8)
  })

  it('vocabularyRichness ∈ (0, 1]', () => {
    const f = extractFeatures(SAMPLE_A)
    expect(f.vocabularyRichness).toBeGreaterThan(0)
    expect(f.vocabularyRichness).toBeLessThanOrEqual(1)
  })

  it('functionWordRatio > 0 for English text', () => {
    const f = extractFeatures(SAMPLE_A)
    expect(f.functionWordRatio).toBeGreaterThan(0.1)
  })

  it('yulesK > 0 for natural text', () => {
    const f = extractFeatures(SAMPLE_A)
    expect(f.yulesK).toBeGreaterThan(0)
  })

  it('charBigrams is populated', () => {
    const f = extractFeatures(SAMPLE_A)
    expect(f.charBigrams.size).toBeGreaterThan(20)
  })

  it('wordLengthDist has 15 bins', () => {
    const f = extractFeatures(SAMPLE_A)
    expect(f.wordLengthDist.length).toBe(15)
  })

  it('wordLengthDist sums to approximately 1', () => {
    const f = extractFeatures(SAMPLE_A)
    const sum = f.wordLengthDist.reduce((a, b) => a + b, 0)
    expect(sum).toBeCloseTo(1, 2)
  })

  it('empty text produces zeros', () => {
    const f = extractFeatures('')
    expect(f.wordCount).toBe(0)
    expect(f.avgWordLength).toBe(0)
  })

  it('detects contractions', () => {
    const f = extractFeatures("I don't think that's right. Can't you see it won't work?")
    expect(f.contractionRate).toBeGreaterThan(0)
  })

  it('detects exclamation marks', () => {
    const f = extractFeatures('This is great! Amazing! Wow!')
    expect(f.exclamationRate).toBeGreaterThan(0)
  })

  it('detects question marks', () => {
    const f = extractFeatures('Is this right? Are you sure? Why not?')
    expect(f.questionRate).toBeGreaterThan(0)
  })
})

describe('cosineSimilarity', () => {
  it('identical vectors = 1', () => {
    expect(cosineSimilarity([1, 2, 3], [1, 2, 3])).toBeCloseTo(1, 10)
  })

  it('orthogonal vectors = 0', () => {
    expect(cosineSimilarity([1, 0], [0, 1])).toBeCloseTo(0, 10)
  })

  it('opposite vectors = -1', () => {
    expect(cosineSimilarity([1, 0], [-1, 0])).toBeCloseTo(-1, 10)
  })

  it('result ∈ [-1, 1]', () => {
    for (let i = 0; i < 50; i++) {
      const a = Array.from({ length: 10 }, () => Math.random() * 2 - 1)
      const b = Array.from({ length: 10 }, () => Math.random() * 2 - 1)
      const sim = cosineSimilarity(a, b)
      expect(sim).toBeGreaterThanOrEqual(-1 - 1e-10)
      expect(sim).toBeLessThanOrEqual(1 + 1e-10)
    }
  })

  it('symmetric: cos(a,b) = cos(b,a)', () => {
    const a = [1, 3, 5, 7]
    const b = [2, 4, 6, 8]
    expect(cosineSimilarity(a, b)).toBeCloseTo(cosineSimilarity(b, a), 10)
  })
})

describe('featureVector', () => {
  it('returns consistent length', () => {
    const vA = featureVector(extractFeatures(SAMPLE_A))
    const vB = featureVector(extractFeatures(SAMPLE_B))
    expect(vA.length).toBe(vB.length)
    expect(vA.length).toBe(30) // 15 scalar + 15 word length bins
  })
})

describe('compareWriteprints', () => {
  it('same text = very high similarity', () => {
    const result = compareWriteprints(SAMPLE_A, SAMPLE_A)
    expect(result.similarity).toBeGreaterThan(0.95)
  })

  it('similar author, different topic > different author', () => {
    const sameAuthor = compareWriteprints(SAMPLE_A, SAMPLE_A_VARIANT)
    const diffAuthor = compareWriteprints(SAMPLE_A, SAMPLE_B)
    expect(sameAuthor.similarity).toBeGreaterThan(diffAuthor.similarity)
  })

  it('similarity ∈ [0, 1]', () => {
    const result = compareWriteprints(SAMPLE_A, SAMPLE_B)
    expect(result.similarity).toBeGreaterThanOrEqual(0)
    expect(result.similarity).toBeLessThanOrEqual(1)
  })

  it('returns both feature sets', () => {
    const result = compareWriteprints(SAMPLE_A, SAMPLE_B)
    expect(result.featuresA.wordCount).toBeGreaterThan(0)
    expect(result.featuresB.wordCount).toBeGreaterThan(0)
  })

  it('symmetric: compare(a,b) ≈ compare(b,a)', () => {
    const ab = compareWriteprints(SAMPLE_A, SAMPLE_B)
    const ba = compareWriteprints(SAMPLE_B, SAMPLE_A)
    expect(ab.similarity).toBeCloseTo(ba.similarity, 5)
  })

  it('different writing styles produce lower similarity', () => {
    // technical security writing vs casual cooking instructions
    const result = compareWriteprints(SAMPLE_A, SAMPLE_B)
    expect(result.similarity).toBeLessThan(0.90)
  })
})
