/**
 * Username and social media profile discovery.
 *
 * Given a username, email, or name, checks major platforms for
 * matching profiles. Cross-platform presence is a strong identity
 * signal — if the same username appears on GitHub, Twitter, and
 * LinkedIn, those accounts likely belong to the same person.
 *
 * Method: HTTP HEAD/GET requests to known profile URL patterns.
 * No scraping, no authentication, no API keys. Just checking
 * if a profile page returns 200 vs 404.
 *
 * Known limitation: ~15% false positive rate on LinkedIn
 * (returns 200 for non-existent profiles). Platform-specific
 * validators reduce this.
 *
 * All passive OSINT. Berkeley Protocol compliant.
 */

import type { Signal, FetchOptions } from '../types.js'
import { fetchWithTimeout } from '../types.js'

/** A social media platform profile check */
export interface PlatformCheck {
  platform: string
  url: string
  exists: boolean
  /** HTTP status code */
  statusCode: number
  /** did we validate beyond just the status code? */
  validated: boolean
  /** profile display name if extractable from response */
  displayName: string | null
}

/** Username enumeration result */
export interface UsernameResult {
  username: string
  platforms: PlatformCheck[]
  /** platforms where the username exists */
  found: string[]
  /** platforms where we're confident it exists (validated) */
  confirmedFound: string[]
  signals: Signal[]
}

interface PlatformConfig {
  name: string
  urlPattern: (username: string) => string
  /** validate that the response is a real profile, not a soft 404 */
  validate?: (body: string, username: string) => boolean
  /** some platforms need specific headers */
  headers?: Record<string, string>
}

const PLATFORMS: PlatformConfig[] = [
  {
    name: 'github',
    urlPattern: (u) => `https://api.github.com/users/${u}`,
    validate: (body) => {
      try { return JSON.parse(body).login !== undefined } catch { return false }
    },
  },
  {
    name: 'twitter',
    urlPattern: (u) => `https://x.com/${u}`,
    // twitter often blocks, so status code is all we have
  },
  {
    name: 'instagram',
    urlPattern: (u) => `https://www.instagram.com/${u}/`,
  },
  {
    name: 'linkedin',
    urlPattern: (u) => `https://www.linkedin.com/in/${u}/`,
    // linkedin returns 200 for non-existent — high false positive
    validate: (body, username) => {
      return body.includes(username) || body.includes('profile-section')
    },
  },
  {
    name: 'reddit',
    urlPattern: (u) => `https://www.reddit.com/user/${u}/about.json`,
    validate: (body) => {
      try { return JSON.parse(body).data?.name !== undefined } catch { return false }
    },
  },
  {
    name: 'medium',
    urlPattern: (u) => `https://medium.com/@${u}`,
  },
  {
    name: 'pinterest',
    urlPattern: (u) => `https://www.pinterest.com/${u}/`,
  },
  {
    name: 'tiktok',
    urlPattern: (u) => `https://www.tiktok.com/@${u}`,
  },
  {
    name: 'youtube',
    urlPattern: (u) => `https://www.youtube.com/@${u}`,
  },
  {
    name: 'gitlab',
    urlPattern: (u) => `https://gitlab.com/api/v4/users?username=${u}`,
    validate: (body) => {
      try { const arr = JSON.parse(body); return Array.isArray(arr) && arr.length > 0 } catch { return false }
    },
  },
  {
    name: 'hackernews',
    urlPattern: (u) => `https://hacker-news.firebaseio.com/v0/user/${u}.json`,
    validate: (body) => {
      try { return JSON.parse(body)?.id !== undefined } catch { return false }
    },
  },
  {
    name: 'keybase',
    urlPattern: (u) => `https://keybase.io/${u}`,
  },
  {
    name: 'mastodon',
    urlPattern: (u) => `https://mastodon.social/@${u}`,
  },
  {
    name: 'npm',
    urlPattern: (u) => `https://registry.npmjs.org/-/user/org.couchdb.user:${u}`,
    validate: (body) => {
      try { return JSON.parse(body).name !== undefined } catch { return false }
    },
  },
]

/**
 * Check if a username exists across social media platforms.
 *
 * @param username - The username to search for
 * @param options - Fetch options + platform filter
 */
export async function checkUsername(
  username: string,
  options: FetchOptions & {
    /** only check these platforms (default: all) */
    platforms?: string[]
    /** max concurrent checks */
    concurrency?: number
  } = {},
): Promise<UsernameResult> {
  const { platforms: filterPlatforms, concurrency = 5 } = options

  const platformsToCheck = filterPlatforms
    ? PLATFORMS.filter(p => filterPlatforms.includes(p.name))
    : PLATFORMS

  const results: PlatformCheck[] = []

  // batch with concurrency limit
  for (let i = 0; i < platformsToCheck.length; i += concurrency) {
    const batch = platformsToCheck.slice(i, i + concurrency)
    const batchResults = await Promise.allSettled(
      batch.map(platform => checkPlatform(username, platform, options)),
    )

    for (const result of batchResults) {
      if (result.status === 'fulfilled') {
        results.push(result.value)
      }
    }

    // small delay between batches to avoid rate limiting
    if (i + concurrency < platformsToCheck.length) {
      await new Promise(r => setTimeout(r, 500))
    }
  }

  const found = results.filter(r => r.exists).map(r => r.platform)
  const confirmedFound = results.filter(r => r.exists && r.validated).map(r => r.platform)

  const signals: Signal[] = []

  if (found.length > 0) {
    signals.push({
      source: 'social_media',
      observation: `username "${username}" found on ${found.length} platform(s): ${found.join(', ')}`,
      score: Math.min(0.8, found.length * 0.15),
      confidence: confirmedFound.length > 0 ? 0.85 : 0.60,
      informationBits: Math.min(15, found.length * 3),
      rawData: JSON.stringify(results.filter(r => r.exists)),
      sourceUrl: `username-search:${username}`,
    })
  }

  if (confirmedFound.length >= 3) {
    signals.push({
      source: 'social_media',
      observation: `username "${username}" confirmed on ${confirmedFound.length} platforms — strong identity signal`,
      score: 0.85,
      confidence: 0.90,
      informationBits: 12.0,
      rawData: confirmedFound.join(', '),
      sourceUrl: `username-search:${username}`,
    })
  }

  return { username, platforms: results, found, confirmedFound, signals }
}

async function checkPlatform(
  username: string,
  platform: PlatformConfig,
  options: FetchOptions,
): Promise<PlatformCheck> {
  const url = platform.urlPattern(username)

  try {
    const resp = await fetchWithTimeout(url, {
      ...options,
      timeout: options.timeout ?? 8000,
      headers: { ...platform.headers },
    })

    const exists = resp.status === 200
    let validated = false
    let displayName: string | null = null

    if (exists && platform.validate) {
      const body = await resp.text()
      validated = platform.validate(body, username)

      // try to extract display name from GitHub API
      if (platform.name === 'github' && validated) {
        try {
          const data = JSON.parse(body)
          displayName = data.name ?? data.login
        } catch { /* ignore */ }
      }
    } else if (exists) {
      validated = false // no validator = unconfirmed
    }

    return { platform: platform.name, url, exists, statusCode: resp.status, validated, displayName }
  } catch {
    return { platform: platform.name, url, exists: false, statusCode: 0, validated: false, displayName: null }
  }
}

/**
 * Generate username variants from a real name.
 *
 * Given "Giuseppe Giona", generates: giuseppegiona, giuseppe.giona,
 * giuseppe_giona, ggiona, giuseppeg, giona.giuseppe, etc.
 */
export function generateUsernameVariants(firstName: string, lastName: string): string[] {
  const f = firstName.toLowerCase().trim()
  const l = lastName.toLowerCase().trim()
  const fi = f[0] ?? ''

  const variants = new Set<string>()

  variants.add(`${f}${l}`)
  variants.add(`${f}.${l}`)
  variants.add(`${f}_${l}`)
  variants.add(`${f}-${l}`)
  variants.add(`${l}${f}`)
  variants.add(`${l}.${f}`)
  variants.add(`${l}_${f}`)
  variants.add(`${fi}${l}`)
  variants.add(`${fi}.${l}`)
  variants.add(`${fi}_${l}`)
  variants.add(`${f}${l[0] ?? ''}`)
  variants.add(`${l}${fi}`)
  variants.add(`${l}.${fi}`)
  variants.add(`${f}`)
  variants.add(`${l}`)

  // with numbers
  for (const base of [`${f}${l}`, `${fi}${l}`]) {
    variants.add(`${base}1`)
    variants.add(`${base}123`)
    variants.add(`${base}99`)
  }

  return [...variants].filter(v => v.length >= 3)
}
