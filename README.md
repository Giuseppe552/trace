# trace

Attribution investigation tool. Given a target domain, email, or set of reviews, collects signals from public data sources and quantifies how much anonymity the subject retains.

The math is from published papers. Every reliability parameter cites the study it was derived from. Every forensic report references the legislation it operates under. The tool does not make claims it cannot back with numbers.

421 tests. Zero runtime dependencies in core.

## What it does

Collects publicly available data from 8+ sources, feeds signals into a mathematical attribution engine, and produces a forensic report with evidence chain.

The report includes: anonymity reduction in bits (Shannon entropy), evidence fusion with conflict detection (Dempster-Shafer), cross-platform identity correlation (Fellegi-Sunter), coordination timing analysis (KS test), authorship comparison (stylometric features), and a SHA-256 hash chain for evidence integrity.

Every report cites the applicable UK legislation and states the error rate for each module.

## Architecture

```
packages/
  core/       zero dependencies, 260 tests
    entropy/          Shannon entropy, anonymity set quantification
    fusion/           Dempster-Shafer evidence combination
    linkage/          Fellegi-Sunter record linkage, Jaro-Winkler
    graph/            spectral clustering, Fiedler vector, DOT export
    timing/           Kolmogorov-Smirnov test, coordination detection
    stylometry/       Writeprints features, AI text detection
    evidence/         SHA-256 chain, dual-source verification, RFC 3161
    legal/            UK legal framework (12 statutes cited)
    benchmark/        error rate measurement, KS power tables

  collectors/   data source integrations, 151 tests
    ct/               crt.sh — 14B+ certificates
    dns/              all record types, domain age estimation
    whois/            RDAP (RFC 9082), raw WHOIS fallback, reverse, history
    email/            RFC 5322 header forensics
    headers/          platform fingerprinting, tracking ID extraction
    ip/               geolocation, ASN, VPN detection
    reviews/          suspicion heuristics, profile OSINT, behavioral comparison
    social/           username enumeration across 14 platforms
    brand/            typosquat detection, backlink toxicity
    correlation/      cross-domain analysis, frequency-weighted
    monitor/          continuous DNS/CT change detection
    archive/          Wayback Machine evidence preservation
    evidence/         page capture with SHA-256

apps/
  cli/        command-line interface
```

## Usage

```sh
# investigate a domain
npx tsx apps/cli/src/main.ts domain example.com

# deep mode — chains through reverse WHOIS, IP geo, cross-domain correlation
npx tsx apps/cli/src/main.ts domain example.com --deep

# compare writing styles
npx tsx apps/cli/src/main.ts compare sample-a.txt sample-b.txt

# detect coordinated review timing
npx tsx apps/cli/src/main.ts timing timestamps.json

# check if text is AI-generated
npx tsx apps/cli/src/main.ts ai review.txt

# analyze reviews for suspicious patterns
npx tsx apps/cli/src/main.ts reviews reviews.json

# full review attack investigation
npx tsx apps/cli/src/main.ts investigate-reviews attack-input.json

# cross-domain correlation
npx tsx apps/cli/src/main.ts correlate domain1.com domain2.com

# IP geolocation + ASN
npx tsx apps/cli/src/main.ts ip 1.2.3.4

# monitor a domain for changes
npx tsx apps/cli/src/main.ts monitor example.com
```

## Example output

From a real investigation against `example.com`:

```
Starting population: 67.0M (26.0 bits).
Evidence reduced anonymity by 16.6 bits to 9.4 bits (effective set: 698).

Dempster-Shafer evidence fusion across 8 signals:
Belief: 0.339. Plausibility: 0.339. Conflict: 0.980.

Evidence chain: 4 entries, integrity verified (SHA-256).
```

The tool generates three files per investigation:
- `trace-evidence-*.json` — machine-readable evidence chain
- `trace-report-*.md` — forensic narrative with legal citations
- `trace-graph-*.dot` — attribution graph (render with Graphviz)

## Mathematical methods

Each method references the original paper.

| Method | Application | Reference |
|--------|------------|-----------|
| Shannon entropy | Anonymity quantification in bits | Shannon (1948) |
| Dempster-Shafer theory | Evidence fusion with conflict detection | Dempster (1967), Shafer (1976) |
| Fellegi-Sunter model | Cross-platform identity correlation | Fellegi & Sunter (1969) |
| Jaro-Winkler similarity | Approximate string matching | Jaro (1989) |
| Kolmogorov-Smirnov test | Coordinated timing detection | Kolmogorov (1933) |
| Writeprints features | Authorship attribution | Abbasi & Chen (2008) |
| Yule's K | Vocabulary diversity measurement | Yule (1944) |
| Jensen-Shannon divergence | Character bigram comparison | Lin (1991) |
| Spectral clustering | Network community detection | Fiedler (1973) |
| Normalized Laplacian | Graph partitioning | Meiklejohn et al. (2013) |

## Calibration

Reliability parameters are derived from published accuracy studies, not estimated.

| Source | Reliability | Citation |
|--------|------------|----------|
| WHOIS (visible registrant) | 0.92 | ICANN ARS Phase 2 Cycle 6 (2018) |
| WHOIS (GDPR redacted) | 0.10 | 73% of gTLD domains redacted post-GDPR |
| Certificate transparency | 0.87 | Li et al. CCS 2019: ~93% monitor completeness |
| Stylometry (200+ words) | 0.75 | Abbasi & Chen 2008; arXiv 2507.00838 |
| Stylometry (<50 words) | 0.15 | Literature consensus: unreliable |
| IP geolocation (country) | 0.95 | MaxMind: 99.8% country accuracy |
| IP geolocation (city, US/EU) | 0.60 | MaxMind: ~66% within 50km |
| Tracking IDs (GA/GTM) | 0.98 | Property IDs are unique per account |
| Shared CDN nameservers | 0.05 | Millions of domains share these |

Information gain values are computed from population base rates (378.5M total domains, DNIB Q3 2025), not hardcoded.

## Legal framework

Every forensic report cites the applicable legislation. The tool operates within passive OSINT boundaries.

**Evidence admissibility:** Civil Evidence Act 1995, BS 10008:2020, Criminal Practice Direction 19A (2014).

**Investigation legality:** Computer Misuse Act 1990, Data Protection Act 2018, Berkeley Protocol (OHCHR, 2020).

**Remedies for fake review attacks:** DMCC Act 2024 Schedule 20 (fake reviews banned, CMA fines up to 10% global turnover), Defamation Act 2013 s.5 (Norwich Pharmacal orders for identity disclosure), Protection from Harassment Act 1997.

## What it does not do

- The stylometry module has not been benchmarked against a labeled dataset. Confidence intervals widen for short texts. Below 50 words, results are unreliable.
- The AI text detector is statistical only (no neural model). Industry tools like GPTZero achieve 88-92% accuracy. This detector is expected to score lower. It flags indicators for further investigation, not determinations.
- Review suspicion heuristics are keyword-based and trivially evaded by a competent attacker. They catch unsophisticated attacks.
- The evidence chain proves integrity (data wasn't altered after capture) but proving authenticity (data was real when captured) requires independent verification (dual-source DNS, RFC 3161 timestamps).
- IP geolocation accuracy varies by region. City-level is ~66% accurate in the US/EU and lower elsewhere. VPN/proxy detection has unknown false negative rates.
- Certificate transparency data comes from a single monitor (crt.sh). Li et al. found ~6.7% of certificates missing from individual monitors.
- ACPO alignment checks are technical prerequisites only, not a full compliance assessment.

## Tests

```sh
cd packages/core && npx vitest run       # 260 tests
cd packages/collectors && npx vitest run # 161 tests (151 unit + 10 integration)
```

## License

MIT
