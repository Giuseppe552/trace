# Research #2: Information Gain Values

Issue: AUDIT.md #2 — hardcoded information gain constants instead of computed values.

## The problem

Signals have hardcoded `informationBits` values like 20.0 for a WHOIS email or 2.0 for nameservers. These should be computed from I(x) = -log2 p(x) using real population base rates.

## The math

Self-information: I(x) = -log2 p(x)

Where p(x) is the probability of observing this specific value by chance in the relevant population.

Example: if 1 in 8.3 billion email addresses match a specific address, I = -log2(1/8.3B) = 32.9 bits. But that's not right either — the question isn't "how many email addresses exist" but "what's the probability that the person we're investigating has THIS specific email?" That depends on the suspect population, not the global email count.

The correct framing: given a population of N suspects, what fraction would produce this same observable? That's p(x), and I(x) = -log2(p(x)).

## Population base rates (from verified sources)

### Email address
- 8.3 billion email accounts worldwide (Radicati/Statista, 2024)
- An email address is unique by definition (no two people share one)
- p(match by coincidence) ≈ 1 / N_suspects
- For UK population (67M): I = -log2(1/67M) = 26.0 bits (the full prior — email alone identifies)
- In practice: email matching is near-definitive. I = prior_bits (full identification).
- Source: https://financesonline.com/number-of-email-users/

### Domain registrant name
- Not unique. "John Smith" appears on many domains.
- Frequency depends on the name. Common names: low info gain. Rare names: high.
- Approach: use name frequency data. UK has ~67M people, ~400K distinct surnames.
- Average surname frequency: 67M / 400K ≈ 168 people per surname
- I(surname) = -log2(168/67M) = -log2(2.5e-6) ≈ 18.6 bits
- But "Smith" (1.26% of UK pop) gives I = -log2(0.0126) ≈ 6.3 bits
- "Giona" (very rare) gives I ≈ 20+ bits
- Should be computed per-name, not hardcoded.

### Registrar
- ~378M total domains worldwide (Q3 2025, DNIB)
- GoDaddy: 52.5M .com domains → 13.9% of .com
- Namecheap: 11.9M .com domains → 3.2% of .com
- p(same registrar by coincidence) = registrar_share
- GoDaddy: I = -log2(0.139) = 2.8 bits
- Namecheap: I = -log2(0.032) = 5.0 bits
- Small registrar (0.1%): I = -log2(0.001) = 10.0 bits
- Source: https://domainnamewire.com/2025/12/04/cloudflare-enters-top-10-registrars-for-com/

### Nameservers
- Cloudflare DNS: 20.11% market share in DNS services
- ~42M websites use Cloudflare
- p(shared Cloudflare NS by coincidence) ≈ 0.20
- I = -log2(0.20) = 2.3 bits (very low — nearly meaningless for attribution)
- GoDaddy DNS: 33.13% → I = -log2(0.33) = 1.6 bits
- Dedicated/custom NS (used by <0.1% of domains): I = -log2(0.001) = 10.0 bits
- Source: https://6sense.com/tech/domain-name-services/cloudflare-dns-market-share

### IP address (hosting)
- Shared hosting: average 500-2600 domains per IP
- Dedicated IP: ~1 domain per IP (or small number)
- Total IPs in use for web hosting: ~100M (estimate from IPv4 allocation data)
- p(shared IP on shared hosting): 500/378M ≈ 1.3e-6 → I = 19.5 bits... but that's wrong
- The right question: "given two random domains, what's the probability they share an IP?"
- With 378M domains and ~100M IPs, average 3.8 domains per IP
- p(random domain shares IP with target) = 3.8 / 378M ≈ 1e-8 → I = 26.5 bits
- But on shared hosting (500/IP): p = 500/378M ≈ 1.3e-6 → I = 19.5 bits
- On Cloudflare (CDN, anycast): millions share same IPs → I ≈ 1-2 bits
- Must distinguish dedicated vs CDN/shared.

### Country (from IP geolocation)
- Already computed correctly in the code using population ratios
- UK (67M/8B): I = log2(8B/67M) = 6.9 bits
- US (334M/8B): I = log2(8B/334M) = 4.6 bits
- This is correct — leave as is.

### City (from IP geolocation)
- Currently hardcoded at 8.0 bits
- Should be: I = log2(country_pop / city_pop)
- London (9M in 67M UK): I = log2(67M/9M) = 2.9 bits
- Bradford (540K in 67M UK): I = log2(67M/540K) = 6.95 bits
- Rural town (5K in 67M UK): I = log2(67M/5K) = 13.7 bits
- Must compute per-city, not hardcode.

### ASN
- ~75,000 active ASNs worldwide
- p(same ASN by coincidence) = 1/75000 ≈ 1.3e-5
- But ASN distribution is heavily skewed: top 10 ASNs host >50% of traffic
- Cloudflare (AS13335): hosts millions of domains → p ≈ 0.10 → I = 3.3 bits
- Small ISP: hosts thousands → p ≈ 0.001 → I = 10.0 bits
- Must compute per-ASN.

### Google Analytics tracking ID
- Each GA property is unique to an account
- p(two unrelated domains sharing GA ID) ≈ 0 (requires intentional configuration)
- I ≈ prior_bits (full identification equivalent)
- Current 20.0 is reasonable but should be documented as "near-definitive"

### CT (certificate shared SAN)
- p(two domains sharing a certificate by coincidence) is very low
- Shared SANs require the cert requestor to list both domains
- Exception: CDN wildcard certs (*.cloudflaressl.com) — millions share these
- Non-CDN shared cert: I ≈ 15-20 bits
- CDN shared cert: I ≈ 0-2 bits

## Implementation approach

Replace hardcoded constants with a function that computes I(x) from the observation context:

```typescript
function computeInfoGain(type: string, value: string, context: object): number {
  // email: near-definitive → return prior bits
  // registrar: lookup market share → -log2(share)
  // NS: lookup provider share → -log2(share)
  // IP: check if CDN/shared vs dedicated
  // city: lookup city population → log2(country/city)
  // ASN: check if major CDN vs small ISP
  // tracking ID: near-definitive → return prior bits
}
```

Need lookup tables for:
1. Registrar market shares (top 20)
2. NS provider market shares (top 10)
3. CDN detection (known CDN ASNs and IP ranges)
4. City populations (top 500 cities globally, or use an API)

## Sources

- Total domains: 378.5M (Q3 2025, DNIB) https://www.dnib.com/
- GoDaddy .com domains: 52.5M https://domainnamewire.com/2025/12/04/cloudflare-enters-top-10-registrars-for-com/
- Namecheap .com: 11.9M (same source)
- Cloudflare DNS share: 20.11% https://6sense.com/tech/domain-name-services/cloudflare-dns-market-share
- Cloudflare websites: 42M https://w3techs.com/technologies/details/cn-cloudflare
- Email accounts: 8.3B https://financesonline.com/number-of-email-users/
- Domains per IP (shared hosting): 500-2600 https://arxiv.org/pdf/2111.00142
- Active ASNs: ~75,000 (IANA/RIR data)
- Sweeney (2000): 87% uniquely identified by ZIP+DOB+sex https://dataprivacylab.org/projects/identifiability/paper1.pdf

## Status: research complete. Ready to implement.
