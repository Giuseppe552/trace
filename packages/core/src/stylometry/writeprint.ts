/**
 * Stylometric analysis for authorship attribution.
 *
 * Extracts writing style features from text and computes similarity
 * between writing samples. Based on the Writeprints technique
 * (Abbasi & Chen, 2008, ACM TOIS 26(2)) which achieved 94% accuracy
 * differentiating 100 authors using lexical, syntactic, structural,
 * and idiosyncratic features.
 *
 * Application: compare anonymous review text against known writing
 * samples from a suspected author (website copy, social media, etc.).
 *
 * Limitation: short texts (single reviews, <100 words) have significantly
 * lower accuracy. Need multiple samples for reliable attribution.
 *
 * Reference: Abbasi, A. and Chen, H. (2008). "Writeprints: A stylometric
 *   approach to identity-level identification and similarity detection
 *   in cyberspace." ACM TOIS 26(2).
 */

/** Feature vector extracted from a text sample */
export interface StyleFeatures {
  /** average word length in characters */
  avgWordLength: number
  /** average sentence length in words */
  avgSentenceLength: number
  /** standard deviation of sentence length */
  sentenceLengthStd: number
  /** vocabulary richness: unique words / total words (hapax legomena ratio) */
  vocabularyRichness: number
  /** Yule's K measure of vocabulary diversity */
  yulesK: number
  /** frequency of function words (the, a, is, was, etc.) */
  functionWordRatio: number
  /** punctuation frequency (per word) */
  punctuationRate: number
  /** comma frequency (per sentence) */
  commaRate: number
  /** exclamation mark frequency (per sentence) */
  exclamationRate: number
  /** question mark frequency (per sentence) */
  questionRate: number
  /** ratio of sentences starting with a pronoun */
  pronounStartRate: number
  /** ratio of words that are capitalized (not sentence-start) */
  midCapRate: number
  /** average paragraph length in sentences */
  avgParagraphLength: number
  /** contraction usage rate (don't, can't, etc.) */
  contractionRate: number
  /** digit usage rate (numbers in text) */
  digitRate: number
  /** total word count */
  wordCount: number
  /** character bigram frequency distribution (top 50) */
  charBigrams: Map<string, number>
  /** word length distribution (1-15+) */
  wordLengthDist: number[]
}

const FUNCTION_WORDS = new Set([
  'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
  'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
  'should', 'may', 'might', 'shall', 'can', 'need', 'dare', 'ought',
  'used', 'to', 'of', 'in', 'for', 'on', 'with', 'at', 'by', 'from',
  'as', 'into', 'through', 'during', 'before', 'after', 'above', 'below',
  'between', 'out', 'off', 'over', 'under', 'again', 'further', 'then',
  'once', 'and', 'but', 'or', 'nor', 'not', 'so', 'yet', 'both',
  'either', 'neither', 'each', 'every', 'all', 'both', 'few', 'more',
  'most', 'other', 'some', 'such', 'no', 'only', 'own', 'same', 'than',
  'too', 'very', 'just', 'because', 'if', 'when', 'while', 'although',
  'though', 'that', 'which', 'who', 'whom', 'this', 'these', 'those',
  'i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'you', 'your',
  'he', 'him', 'his', 'she', 'her', 'hers', 'it', 'its', 'they',
  'them', 'their', 'what', 'where', 'how', 'why', 'here', 'there',
])

const PRONOUNS = new Set([
  'i', 'we', 'you', 'he', 'she', 'it', 'they', 'me', 'us', 'him',
  'her', 'them', 'my', 'our', 'your', 'his', 'its', 'their',
])

const CONTRACTION_RE = /\b\w+[']\w+\b/g

/**
 * Split text into sentences. Handles common abbreviations.
 */
function splitSentences(text: string): string[] {
  // split on sentence-ending punctuation followed by space + capital or end
  return text
    .split(/(?<=[.!?])\s+(?=[A-Z])|(?<=[.!?])$/)
    .map(s => s.trim())
    .filter(s => s.length > 0)
}

/**
 * Split text into words.
 */
function splitWords(text: string): string[] {
  return text
    .split(/\s+/)
    .map(w => w.replace(/^[^\w]+|[^\w]+$/g, ''))
    .filter(w => w.length > 0)
}

/**
 * Extract style features from a text sample.
 */
export function extractFeatures(text: string): StyleFeatures {
  const sentences = splitSentences(text)
  const words = splitWords(text)
  const lowerWords = words.map(w => w.toLowerCase())
  const totalWords = words.length
  const totalSentences = Math.max(sentences.length, 1)

  // word lengths
  const wordLengths = words.map(w => w.length)
  const avgWordLength = totalWords > 0
    ? wordLengths.reduce((a, b) => a + b, 0) / totalWords
    : 0

  // sentence lengths
  const sentenceLengths = sentences.map(s => splitWords(s).length)
  const avgSentenceLength = sentenceLengths.length > 0
    ? sentenceLengths.reduce((a, b) => a + b, 0) / sentenceLengths.length
    : 0
  const sentenceLengthStd = stdDev(sentenceLengths)

  // vocabulary richness
  const uniqueWords = new Set(lowerWords)
  const vocabularyRichness = totalWords > 0 ? uniqueWords.size / totalWords : 0

  // Yule's K
  const yulesK = computeYulesK(lowerWords)

  // function words
  const functionWordCount = lowerWords.filter(w => FUNCTION_WORDS.has(w)).length
  const functionWordRatio = totalWords > 0 ? functionWordCount / totalWords : 0

  // punctuation
  const punctCount = (text.match(/[.,;:!?'"()\-—]/g) ?? []).length
  const punctuationRate = totalWords > 0 ? punctCount / totalWords : 0
  const commaCount = (text.match(/,/g) ?? []).length
  const commaRate = commaCount / totalSentences
  const exclamationCount = (text.match(/!/g) ?? []).length
  const exclamationRate = exclamationCount / totalSentences
  const questionCount = (text.match(/\?/g) ?? []).length
  const questionRate = questionCount / totalSentences

  // pronoun starts
  let pronounStarts = 0
  for (const s of sentences) {
    const firstWord = splitWords(s)[0]?.toLowerCase()
    if (firstWord && PRONOUNS.has(firstWord)) pronounStarts++
  }
  const pronounStartRate = pronounStarts / totalSentences

  // mid-sentence capitals
  let midCaps = 0
  for (let i = 0; i < words.length; i++) {
    const w = words[i]
    // skip first word of sentences (approximate: after period)
    if (i > 0 && /^[A-Z]/.test(w) && !/[.!?]$/.test(words[i - 1])) {
      midCaps++
    }
  }
  const midCapRate = totalWords > 1 ? midCaps / (totalWords - 1) : 0

  // paragraphs
  const paragraphs = text.split(/\n\s*\n/).filter(p => p.trim().length > 0)
  const avgParagraphLength = paragraphs.length > 0
    ? paragraphs.reduce((sum, p) => sum + splitSentences(p).length, 0) / paragraphs.length
    : totalSentences

  // contractions
  const contractions = text.match(CONTRACTION_RE) ?? []
  const contractionRate = totalWords > 0 ? contractions.length / totalWords : 0

  // digits
  const digitCount = (text.match(/\d/g) ?? []).length
  const digitRate = text.length > 0 ? digitCount / text.length : 0

  // character bigrams
  const charBigrams = new Map<string, number>()
  const cleanText = text.toLowerCase().replace(/\s+/g, ' ')
  for (let i = 0; i < cleanText.length - 1; i++) {
    const bigram = cleanText.slice(i, i + 2)
    charBigrams.set(bigram, (charBigrams.get(bigram) ?? 0) + 1)
  }
  // normalise to frequencies
  const bigramTotal = cleanText.length - 1
  if (bigramTotal > 0) {
    for (const [k, v] of charBigrams) {
      charBigrams.set(k, v / bigramTotal)
    }
  }

  // word length distribution (1-15+)
  const wordLengthDist = new Array(15).fill(0)
  for (const len of wordLengths) {
    const idx = Math.min(len, 15) - 1
    if (idx >= 0) wordLengthDist[idx]++
  }
  if (totalWords > 0) {
    for (let i = 0; i < wordLengthDist.length; i++) {
      wordLengthDist[i] /= totalWords
    }
  }

  return {
    avgWordLength,
    avgSentenceLength,
    sentenceLengthStd,
    vocabularyRichness,
    yulesK,
    functionWordRatio,
    punctuationRate,
    commaRate,
    exclamationRate,
    questionRate,
    pronounStartRate,
    midCapRate,
    avgParagraphLength,
    contractionRate,
    digitRate,
    wordCount: totalWords,
    charBigrams,
    wordLengthDist,
  }
}

/**
 * Yule's K measure of vocabulary diversity.
 *
 * K = 10^4 × (M₂ - M₁) / M₁²
 *
 * where M₁ = total words, M₂ = Σ i² × f(i) for word frequency i.
 * Lower K = more diverse vocabulary. Typical range: 20-200.
 */
function computeYulesK(words: string[]): number {
  if (words.length === 0) return 0

  const freq = new Map<string, number>()
  for (const w of words) {
    freq.set(w, (freq.get(w) ?? 0) + 1)
  }

  // frequency of frequencies
  const freqOfFreq = new Map<number, number>()
  for (const count of freq.values()) {
    freqOfFreq.set(count, (freqOfFreq.get(count) ?? 0) + 1)
  }

  const M1 = words.length
  let M2 = 0
  for (const [i, fi] of freqOfFreq) {
    M2 += i * i * fi
  }

  if (M1 <= 1) return 0
  return 10000 * (M2 - M1) / (M1 * M1)
}

/**
 * Compute cosine similarity between two feature vectors.
 *
 * Uses the scalar features (not bigrams) for a quick comparison.
 * For full Writeprints accuracy, use compareWriteprints which
 * includes character bigram similarity.
 */
export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length || a.length === 0) return 0

  let dot = 0, normA = 0, normB = 0
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i]
    normA += a[i] * a[i]
    normB += b[i] * b[i]
  }

  const denom = Math.sqrt(normA) * Math.sqrt(normB)
  return denom > 0 ? dot / denom : 0
}

/**
 * Convert scalar features to a normalised vector for comparison.
 */
export function featureVector(f: StyleFeatures): number[] {
  return [
    f.avgWordLength,
    f.avgSentenceLength / 50,        // normalise to ~[0,1]
    f.sentenceLengthStd / 20,
    f.vocabularyRichness,
    f.yulesK / 200,                   // normalise typical range
    f.functionWordRatio,
    f.punctuationRate,
    f.commaRate / 3,
    f.exclamationRate,
    f.questionRate,
    f.pronounStartRate,
    f.midCapRate,
    f.avgParagraphLength / 10,
    f.contractionRate,
    f.digitRate,
    ...f.wordLengthDist,
  ]
}

/**
 * Compare two text samples and return a similarity score.
 *
 * Combines:
 * - Cosine similarity of scalar feature vectors (60% weight)
 * - Character bigram overlap via Jensen-Shannon divergence (40% weight)
 *
 * Returns a score in [0, 1] where 1 = identical writing style.
 */
export function compareWriteprints(textA: string, textB: string): {
  similarity: number
  scalarSimilarity: number
  bigramSimilarity: number
  featuresA: StyleFeatures
  featuresB: StyleFeatures
} {
  const featuresA = extractFeatures(textA)
  const featuresB = extractFeatures(textB)

  const vecA = featureVector(featuresA)
  const vecB = featureVector(featuresB)
  const scalarSimilarity = cosineSimilarity(vecA, vecB)

  // character bigram similarity via 1 - JSD
  const bigramSimilarity = 1 - jensenShannonDivergence(
    featuresA.charBigrams,
    featuresB.charBigrams,
  )

  const similarity = 0.6 * scalarSimilarity + 0.4 * bigramSimilarity

  return { similarity, scalarSimilarity, bigramSimilarity, featuresA, featuresB }
}

/**
 * Jensen-Shannon divergence between two distributions.
 * JSD ∈ [0, 1] when using log base 2.
 * JSD = 0 when distributions are identical.
 */
function jensenShannonDivergence(
  p: Map<string, number>,
  q: Map<string, number>,
): number {
  const allKeys = new Set([...p.keys(), ...q.keys()])
  const m = new Map<string, number>()

  for (const key of allKeys) {
    m.set(key, ((p.get(key) ?? 0) + (q.get(key) ?? 0)) / 2)
  }

  return (klDivergence(p, m) + klDivergence(q, m)) / 2
}

function klDivergence(p: Map<string, number>, q: Map<string, number>): number {
  let kl = 0
  for (const [key, pVal] of p) {
    if (pVal <= 0) continue
    const qVal = q.get(key) ?? 0
    if (qVal <= 0) continue
    kl += pVal * Math.log2(pVal / qVal)
  }
  return kl
}

function stdDev(values: number[]): number {
  if (values.length < 2) return 0
  const mean = values.reduce((a, b) => a + b, 0) / values.length
  const variance = values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / (values.length - 1)
  return Math.sqrt(variance)
}
