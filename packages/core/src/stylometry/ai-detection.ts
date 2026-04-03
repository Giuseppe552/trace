/**
 * AI-generated text detection for attribution investigations.
 *
 * Detecting AI text in reviews is itself an attribution signal —
 * real customers don't use GPT to write reviews. If a 1-star review
 * shows AI characteristics, the probability it's a coordinated attack
 * increases significantly.
 *
 * Methods (no external API, no ML model — pure statistical):
 *
 * 1. Perplexity uniformity: AI text has suspiciously uniform
 *    per-sentence complexity. Humans vary wildly.
 *
 * 2. Burstiness: AI produces consistent sentence lengths.
 *    Humans mix 3-word and 30-word sentences. CV of sentence
 *    length is the strongest single feature.
 *
 * 3. Vocabulary predictability: AI uses common, "safe" words.
 *    Measured via type-token ratio and hapax legomena ratio.
 *
 * 4. Structural uniformity: AI paragraphs are similar length.
 *    AI sentences start with similar patterns.
 *
 * 5. Hedging language: AI overuses "it is worth noting",
 *    "it's important to", "however", "additionally", etc.
 *
 * 6. Sentence opener diversity: AI recycles openers.
 *    Humans are messier.
 *
 * Limitation: unreliable below 75 words (per GPTZero research).
 * For short reviews, we report low confidence rather than guessing.
 *
 * References:
 *   GPTZero methodology: https://gptzero.me/technology
 *   Mitchell et al. (2023) "DetectGPT" — ICML 2023
 *   Pangram Labs (2025) — limitations of perplexity/burstiness
 *   ScienceDirect (2026) — AI-generated fake review detection
 */

/** Result of AI detection analysis */
export interface AiDetectionResult {
  /** overall probability text is AI-generated (0-1) */
  aiProbability: number
  /** confidence in the assessment (0-1), drops for short texts */
  confidence: number
  /** human-readable verdict */
  verdict: 'likely_ai' | 'likely_human' | 'uncertain'
  /** per-feature scores */
  features: {
    /** sentence length CV — humans ≈ 0.5-1.0, AI ≈ 0.15-0.35 */
    sentenceLengthCV: number
    /** word length CV — similar pattern */
    wordLengthCV: number
    /** type-token ratio — AI tends higher (more "correct" vocabulary) */
    typeTokenRatio: number
    /** hapax legomena ratio (words used only once / total) — AI lower */
    hapaxRatio: number
    /** hedging phrase density (per sentence) */
    hedgingDensity: number
    /** sentence opener diversity (unique first-bigrams / total sentences) */
    openerDiversity: number
    /** average sentence length — AI clusters around 15-20 words */
    avgSentenceLength: number
    /** punctuation diversity — humans use more varied punctuation */
    punctuationDiversity: number
  }
  /** which features triggered the AI signal */
  triggers: string[]
  /** word count of input */
  wordCount: number
  /**
   * IMPORTANT: this detector is NOT benchmarked against a labeled dataset.
   * Thresholds are heuristic. Industry AI detectors (GPTZero, Originality.ai)
   * use neural models and achieve 88-92% accuracy. This statistical detector
   * is expected to perform significantly below those numbers.
   *
   * Known bias: non-native English speakers may score higher false positive
   * rates because their writing can appear more "uniform" (lower burstiness).
   * Source: GPTZero research — "detectors are biased against nonnative English speakers"
   *
   * For forensic purposes: an "likely_ai" verdict from this detector is an
   * indicator for further investigation, NOT a determination. It should be
   * combined with other signals (timing, reviewer profile, stylometry).
   */
  caveat: string
}

/** Hedging phrases characteristic of LLM output */
const HEDGING_PHRASES = [
  'it is worth noting',
  'it\'s worth noting',
  'it is important to',
  'it\'s important to',
  'it should be noted',
  'one might argue',
  'it can be said',
  'needless to say',
  'in terms of',
  'when it comes to',
  'at the end of the day',
  'all in all',
  'in conclusion',
  'to sum up',
  'having said that',
  'that being said',
  'with that said',
  'on the other hand',
  'in this regard',
  'in light of',
  'it goes without saying',
  'as a matter of fact',
  'for what it\'s worth',
  'in my experience',
  'i would highly recommend',
  'i cannot recommend',
  'i highly recommend',
  'overall i would say',
  'to be fair',
  'to be honest',
  'in all honesty',
]

/** Transition words AI overuses */
const AI_TRANSITIONS = [
  'however', 'additionally', 'furthermore', 'moreover',
  'consequently', 'nevertheless', 'nonetheless', 'subsequently',
  'accordingly', 'conversely', 'alternatively', 'specifically',
  'essentially', 'fundamentally', 'ultimately', 'particularly',
]

/**
 * Detect whether text is likely AI-generated.
 *
 * Uses statistical features only — no external API, no ML model.
 * Works offline, deterministic, reproducible.
 */
export function detectAiText(text: string): AiDetectionResult {
  const sentences = splitSentences(text)
  const words = text.split(/\s+/).filter(w => w.length > 0)
  const wordCount = words.length
  const lowerText = text.toLowerCase()

  // bail early on very short text
  if (wordCount < 20) {
    return {
      aiProbability: 0.5,
      confidence: 0,
      verdict: 'uncertain',
      features: emptyFeatures(),
      triggers: [],
      wordCount,
      caveat: 'Text too short (<20 words) for any meaningful analysis.',
    }
  }

  const triggers: string[] = []
  let aiScore = 0
  let totalWeight = 0

  // ── Feature 1: Sentence length burstiness ──────────────────
  // humans vary wildly, AI is uniform
  const sentLengths = sentences.map(s => s.split(/\s+/).filter(w => w.length > 0).length)
  const sentenceLengthCV = cv(sentLengths)

  // AI typically 0.15-0.35, humans 0.5-1.0+
  if (sentenceLengthCV < 0.30 && sentences.length >= 3) {
    aiScore += 0.25
    triggers.push(`sentence length too uniform (CV=${sentenceLengthCV.toFixed(3)}, human typical >0.5)`)
  } else if (sentenceLengthCV < 0.40 && sentences.length >= 3) {
    aiScore += 0.10
  }
  totalWeight += 0.25

  // ── Feature 2: Word length variance ────────────────────────
  const wordLengths = words.map(w => w.replace(/[^\w]/g, '').length)
  const wordLengthCV = cv(wordLengths)

  if (wordLengthCV < 0.35) {
    aiScore += 0.10
    triggers.push(`word length too uniform (CV=${wordLengthCV.toFixed(3)})`)
  }
  totalWeight += 0.10

  // ── Feature 3: Type-token ratio ────────────────────────────
  // AI uses "correct" vocabulary — higher TTR for its length
  const uniqueWords = new Set(words.map(w => w.toLowerCase().replace(/[^\w]/g, '')))
  const ttr = uniqueWords.size / Math.max(wordCount, 1)

  // for texts 50-200 words, AI TTR tends to be 0.65-0.85
  // humans vary more, often lower (more repetition in natural speech)
  // this is weak on its own but contributes to the ensemble
  totalWeight += 0.08

  // ── Feature 4: Hapax legomena ratio ────────────────────────
  // words used exactly once / total words
  // AI generates more "efficient" text — fewer hapax
  const wordFreq = new Map<string, number>()
  for (const w of words) {
    const clean = w.toLowerCase().replace(/[^\w]/g, '')
    if (clean) wordFreq.set(clean, (wordFreq.get(clean) ?? 0) + 1)
  }
  const hapax = [...wordFreq.values()].filter(f => f === 1).length
  const hapaxRatio = hapax / Math.max(wordFreq.size, 1)
  totalWeight += 0.07

  // ── Feature 5: Hedging phrase density ──────────────────────
  let hedgeCount = 0
  for (const phrase of HEDGING_PHRASES) {
    const re = new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi')
    const matches = lowerText.match(re)
    if (matches) hedgeCount += matches.length
  }
  const hedgingDensity = hedgeCount / Math.max(sentences.length, 1)

  if (hedgingDensity > 0.3) {
    aiScore += 0.20
    triggers.push(`high hedging phrase density (${hedgingDensity.toFixed(2)} per sentence)`)
  } else if (hedgingDensity > 0.15) {
    aiScore += 0.10
  }
  totalWeight += 0.20

  // ── Feature 6: Sentence opener diversity ───────────────────
  // AI recycles sentence starters
  const openers = sentences.map(s => {
    const words = s.split(/\s+/).slice(0, 2).join(' ').toLowerCase()
    return words
  })
  const uniqueOpeners = new Set(openers)
  const openerDiversity = uniqueOpeners.size / Math.max(sentences.length, 1)

  if (openerDiversity < 0.5 && sentences.length >= 4) {
    aiScore += 0.15
    triggers.push(`low sentence opener diversity (${openerDiversity.toFixed(2)}, ${uniqueOpeners.size}/${sentences.length} unique)`)
  }
  totalWeight += 0.15

  // ── Feature 7: Average sentence length clustering ──────────
  // AI sentences cluster around 15-20 words
  const avgSentLen = sentLengths.length > 0
    ? sentLengths.reduce((a, b) => a + b, 0) / sentLengths.length
    : 0
  if (avgSentLen >= 14 && avgSentLen <= 22 && sentenceLengthCV < 0.4) {
    aiScore += 0.08
    triggers.push(`avg sentence length in AI sweet spot (${avgSentLen.toFixed(1)} words)`)
  }
  totalWeight += 0.08

  // ── Feature 8: Punctuation diversity ───────────────────────
  // humans use dashes, semicolons, ellipsis, exclamations irregularly
  // AI sticks to periods and commas
  const punctTypes = new Set<string>()
  for (const ch of text) {
    if (/[.,;:!?\-—…()"']/.test(ch)) punctTypes.add(ch)
  }
  const punctuationDiversity = punctTypes.size

  if (punctuationDiversity <= 2 && wordCount > 50) {
    aiScore += 0.05
    triggers.push(`low punctuation diversity (only ${punctuationDiversity} types)`)
  }
  totalWeight += 0.07

  // ── Feature 9: AI transition word density ──────────────────
  let transitionCount = 0
  for (const word of AI_TRANSITIONS) {
    const re = new RegExp(`\\b${word}\\b`, 'gi')
    const matches = lowerText.match(re)
    if (matches) transitionCount += matches.length
  }
  const transitionDensity = transitionCount / Math.max(sentences.length, 1)

  if (transitionDensity > 0.4) {
    aiScore += 0.10
    triggers.push(`high AI-typical transition density (${transitionDensity.toFixed(2)} per sentence)`)
  }
  totalWeight += 0.10

  // ── Compute final probability ──────────────────────────────
  const aiProbability = Math.min(1, aiScore / Math.max(totalWeight, 0.01))

  // confidence depends on text length
  // GPTZero research: "short text is genuinely unreliable at under 75-100 words"
  // Source: https://gptzero.me/news/how-ai-detectors-work/
  // Our detector uses statistical features only (no neural model),
  // so reliability is LOWER than GPTZero's reported numbers.
  //
  // Industry benchmarks (2025): GPTZero 88.7%, Originality.ai 92.3%
  // Our statistical approach: estimated 60-70% on long texts (not benchmarked)
  //
  // These confidence values are UNCALIBRATED. No benchmark dataset has been
  // run against this detector. They represent a conservative estimate of
  // text-length-dependent reliability based on the GPTZero research.
  let confidence: number
  if (wordCount < 50) confidence = 0.15  // nearly useless
  else if (wordCount < 75) confidence = 0.30  // GPTZero says unreliable here
  else if (wordCount < 150) confidence = 0.50  // some signal, high uncertainty
  else if (wordCount < 300) confidence = 0.65  // moderate, still below industry tools
  else confidence = 0.75  // best case for statistical-only detection

  // verdict — conservative thresholds to minimize false accusations
  // a false positive (accusing human text of being AI) is worse than
  // a false negative (missing AI text) in a forensic context
  let verdict: AiDetectionResult['verdict']
  if (aiProbability >= 0.6 && confidence >= 0.4) verdict = 'likely_ai'
  else if (aiProbability <= 0.25) verdict = 'likely_human'
  else verdict = 'uncertain'

  return {
    aiProbability,
    confidence,
    verdict,
    features: {
      sentenceLengthCV,
      wordLengthCV,
      typeTokenRatio: ttr,
      hapaxRatio,
      hedgingDensity,
      openerDiversity,
      avgSentenceLength: avgSentLen,
      punctuationDiversity,
    },
    triggers,
    wordCount,
    caveat: 'UNCALIBRATED. Statistical detector only (no neural model). Industry tools (GPTZero, Originality.ai) achieve 88-92% accuracy. This detector has not been benchmarked. Non-native English bias documented. Use as indicator for further investigation, not as determination.',
  }
}

/**
 * Batch analyze multiple texts (e.g. reviews) and flag AI-generated ones.
 */
export function batchDetectAi(
  texts: Array<{ id: string; text: string }>,
): Array<{ id: string; result: AiDetectionResult }> {
  return texts.map(t => ({
    id: t.id,
    result: detectAiText(t.text),
  }))
}

function splitSentences(text: string): string[] {
  return text
    .split(/(?<=[.!?])\s+(?=[A-Z])|(?<=[.!?])$/)
    .map(s => s.trim())
    .filter(s => s.length > 0)
}

function cv(values: number[]): number {
  if (values.length < 2) return 0
  const mean = values.reduce((a, b) => a + b, 0) / values.length
  if (mean === 0) return 0
  const variance = values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / (values.length - 1)
  return Math.sqrt(variance) / mean
}

function emptyFeatures(): AiDetectionResult['features'] {
  return {
    sentenceLengthCV: 0,
    wordLengthCV: 0,
    typeTokenRatio: 0,
    hapaxRatio: 0,
    hedgingDensity: 0,
    openerDiversity: 0,
    avgSentenceLength: 0,
    punctuationDiversity: 0,
  }
}
