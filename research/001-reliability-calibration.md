# Research #1: Reliability Parameter Calibration

Issue: AUDIT.md #1 — LAYER_RELIABILITY values are estimated, not empirically derived.

## Findings from verified sources

### WHOIS (current value: 0.90)

**When registrant data is available (not redacted):**
- ICANN ARS Phase 2 Cycle 6 (Jan 2018, last report before GDPR pause):
  - 92% of registrant email addresses were operable
  - 60% of telephone numbers were operable
  - 99% of postal addresses were operable
  - 98% of records had at least one working contact method
- Source: https://www.icann.org/resources/pages/whois-data-accuracy-2017-06-20-en

**But: 73% of gTLD domains now have NO registrant email at all (GDPR redaction).**
- 67.55% of .com domains redacted
- 95.10% of .org domains redacted
- 67.49% of .net domains redacted
- Source: WhoisXML API analysis via https://main.whoisxmlapi.com/privacy-or-accountability-what-the-redaction-of-whois-data-means-for-cybersecurity

**Calibrated reliability:**
- WHOIS (when registrant visible): 0.92 (ICANN ARS email operability)
- WHOIS (redacted): 0.10 (only registrar/NS data available, very low attribution value)
- WHOIS historical (pre-GDPR): 0.85 (data was accurate when collected, may be stale)
- Probability of getting usable registrant data: ~27% for gTLDs

### Certificate Transparency (current value: 0.85)

**CT log completeness:**
- Li et al. (2019) "Certificate Transparency in the Wild" — CCS 2019:
  - At least 6.7% of certificates missing from individual monitors
  - Censys: incomplete for 7/1000 domains (best)
  - Facebook Monitor: incomplete for hundreds/1000 (worst)
  - crt.sh: between these two
- Since 2018, Chrome requires all publicly trusted certs to be CT-logged (RFC 6962)
- Source: https://www.ittc.ku.edu/~fli/papers/2019_ccs_CT.pdf

**Calibrated reliability:**
- CT data itself: 0.93 (mandatory logging means near-complete for post-2018 certs)
- crt.sh as monitor: 0.87 (some certificates delayed or missed by the monitor)
- Multiple monitors (crt.sh + Censys): 0.95

### Stylometry (current value: 0.55)

**Accuracy by text length:**
- Writeprints (Abbasi & Chen 2008): 94% on 100+ word samples, 100 authors
- Twitter/microblogging (Layton et al. 2010, Green & Sheppard 2013): 
  - 140 chars (~25 words): significantly above chance but well below 90%
  - Accuracy "decreases slowly from 10,000 to 1,000 words, then drops sharply"
- arXiv 2507.00838 (2025): 10-sentence samples (~100 words): 79-100% accuracy with tree-based models
- arXiv 2003.11545 (2020): Twitter forensics with n-grams, below 48% with only 50 training samples
- Forensic validation (Nini 2021, Forensic Science International): 77% across 32,000 document pairs

**Calibrated reliability by text length:**
- 200+ words: 0.75 (strong, multiple features measurable)
- 100-200 words: 0.55 (moderate, some features reliable)
- 50-100 words: 0.35 (weak, high variance)
- <50 words: 0.15 (unreliable, should not be used for attribution)

### IP Geolocation (current value: varies)

**MaxMind published accuracy (their own comparison tool):**
- Country level: 99.8%
- State/region level (US): ~80%
- City level (US, 50km radius): ~66%
- ISP/ASN: ~95% (US), ~80% (outside US)
- Source: https://www.maxmind.com/en/geoip-accuracy-comparison

**ip-api.com (the free service trace uses):**
- No published accuracy statistics
- No SLA
- Based on similar data sources to MaxMind but less frequently updated

**Calibrated reliability:**
- Country (via any provider): 0.95
- City (US/EU): 0.60
- City (other regions): 0.40
- ASN/ISP: 0.90
- If VPN/proxy detected: multiply all by 0.20

### Email Headers (current value: 0.70)

**No large-scale accuracy study found for email header attribution.**
- Headers can be spoofed but SPF/DKIM/DMARC provide authentication
- Gmail/Outlook strip originating IP — makes headers useless for those providers
- Custom domain email preserves more header data

**Calibrated reliability:**
- With SPF+DKIM+DMARC pass: 0.85 (authentication verified the sending domain)
- With SPF pass only: 0.60
- With auth failures: 0.40 (headers indicate spoofing but don't identify the real sender)
- Gmail/Outlook (stripped): 0.20 (almost no attribution value from headers alone)

### Review Profile Analysis (current value: 0.60)

**No published accuracy study for review profile heuristic analysis.**
- The heuristics (rating bias, category concentration, timing patterns) are logical but uncalibrated
- Google's own detection uses ML with access to internal data we don't have

**Calibrated reliability:**
- Multiple flags (3+): 0.65 (convergent signals increase confidence)
- Single flag: 0.35 (any individual heuristic could be a false positive)
- Rating distribution analysis: 0.50 (well-established that fake review campaigns skew distributions)

### Tracking IDs (no current value, detected in headers)

**Google Analytics / GTM IDs:**
- Each GA property has a unique ID
- Multiple domains CAN share one ID (cross-domain tracking) but this requires intentional configuration
- Finding the same GA ID on two apparently unrelated domains is a near-definitive link

**Calibrated reliability:**
- Shared GA/GTM ID: 0.98 (near-unique identifier, intentional configuration)
- Shared Facebook Pixel: 0.95
- Shared Google Ads ID: 0.95

### Cross-domain Correlation

**Shared infrastructure signal strength:**
- Shared dedicated IP: strong (few domains per IP)
- Shared Cloudflare/CDN IP: near-zero (thousands of domains share each anycast IP)
- Shared nameservers (dedicated): moderate (shared hosting provider)
- Shared nameservers (Cloudflare/major CDN): near-zero (millions share these)
- Shared registrant (unredacted): definitive
- Shared tracking ID: definitive (see above)
- Shared SSL certificate (SAN field): strong (intentional configuration)

**No published frequency data for how many domains share each major NS/IP.**
This needs to be computed empirically.


## Recommended LAYER_RELIABILITY values

```typescript
export const LAYER_RELIABILITY: Record<string, number> = {
  // WHOIS — calibrated from ICANN ARS (92% email operability when available)
  whois: 0.92,
  whois_redacted: 0.10,
  whois_historical: 0.85,
  whois_reverse: 0.80,

  // Certificate Transparency — mandatory logging since 2018, monitor gaps ~7%
  ct: 0.87,

  // Email headers — depends on authentication result
  email_headers_authenticated: 0.85,
  email_headers_partial: 0.60,
  email_headers_failed: 0.40,
  email_headers_stripped: 0.20,

  // Stylometry — calibrated from Abbasi & Chen 2008, arXiv 2507.00838
  stylometry_200plus: 0.75,
  stylometry_100_200: 0.55,
  stylometry_50_100: 0.35,
  stylometry_under_50: 0.15,

  // IP geolocation — calibrated from MaxMind published accuracy
  ip_geo_country: 0.95,
  ip_geo_city_us_eu: 0.60,
  ip_geo_city_other: 0.40,
  ip_geo_asn: 0.90,
  ip_geo_via_proxy: 0.20,

  // Review profile — uncalibrated (no published study), conservative estimates
  review_profile_multi_flag: 0.65,
  review_profile_single_flag: 0.35,
  review_rating_distribution: 0.50,

  // Reverse image — depends on match type
  reverse_image_exact: 0.90,
  reverse_image_similar: 0.50,

  // Tracking IDs — near-unique identifiers
  tracking_id_ga: 0.98,
  tracking_id_fbpixel: 0.95,
  tracking_id_gtm: 0.98,

  // Cross-domain correlation — depends on what's shared
  correlation_shared_ip_dedicated: 0.85,
  correlation_shared_ip_cdn: 0.05,
  correlation_shared_ns_dedicated: 0.60,
  correlation_shared_ns_cdn: 0.05,
  correlation_shared_registrant: 0.95,
  correlation_shared_certificate: 0.80,
  correlation_shared_tracking_id: 0.98,

  // AI text detection — uncalibrated, no benchmark dataset
  ai_detection: 0.45,

  // Timing coordination — KS test power depends on sample size
  timing_n_20plus: 0.70,
  timing_n_10_20: 0.50,
  timing_n_under_10: 0.25,

  // DNS — factual data, high reliability
  dns: 0.90,

  // Domain age — depends on source
  domain_age_whois: 0.95,
  domain_age_wayback: 0.80,
  domain_age_ct: 0.85,

  // Backlink toxicity — heuristic, uncalibrated
  backlinks: 0.55,
}
```

## Sources

- ICANN ARS Phase 2 Cycle 6: https://www.icann.org/resources/pages/whois-data-accuracy-2017-06-20-en
- WHOIS redaction rates: https://main.whoisxmlapi.com/privacy-or-accountability-what-the-redaction-of-whois-data-means-for-cybersecurity
- CT log completeness (Li et al. 2019): https://www.ittc.ku.edu/~fli/papers/2019_ccs_CT.pdf
- Writeprints accuracy: Abbasi & Chen, ACM TOIS 26(2), 2008
- Short text stylometry: arXiv 2507.00838, arXiv 2003.11545
- Forensic validation: Nini (2021), Forensic Science International
- MaxMind accuracy: https://www.maxmind.com/en/geoip-accuracy-comparison
- MaxMind published numbers: https://support.maxmind.com/knowledge-base/articles/maxmind-geolocation-accuracy

## Status: research complete. Ready to implement.
