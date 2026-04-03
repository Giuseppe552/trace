import { describe, it, expect } from 'vitest'
import { parseWhois } from '../src/whois/lookup.js'

const SAMPLE_WHOIS = `   Domain Name: EXAMPLE.COM
   Registry Domain ID: 2336799_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.iana.org
   Registrar URL: http://www.iana.org
   Updated Date: 2024-08-14T07:01:38Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2025-08-13T04:00:00Z
   Registrar: RESERVED-Internet Assigned Numbers Authority
   Registrar IANA ID: 376
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   DNSSEC: signedDelegation
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/`

const GDPR_WHOIS = `Domain Name: competitor.co.uk
Registry Domain ID: 1234567890-UK
Registrar WHOIS Server: whois.namecheap.com
Registrar URL: http://www.namecheap.com
Updated Date: 2026-01-15T10:22:33Z
Creation Date: 2023-06-20T08:15:00Z
Registry Expiry Date: 2027-06-20T08:15:00Z
Registrar: NameCheap, Inc.
Registrant Name: Redacted for Privacy
Registrant Organization: Privacy service provided by Withheld for Privacy ehf
Registrant Email: contact@withheldforprivacy.com
Registrant Country: IS
Name Server: NS1.DIGITALOCEAN.COM
Name Server: NS2.DIGITALOCEAN.COM
Name Server: NS3.DIGITALOCEAN.COM
Domain Status: clientTransferProhibited`

const VISIBLE_WHOIS = `Domain Name: smallbusiness.com
Registrar: GoDaddy.com, LLC
Updated Date: 2025-12-01T09:00:00Z
Creation Date: 2020-03-15T14:22:00Z
Registry Expiry Date: 2026-03-15T14:22:00Z
Registrant Name: John Smith
Registrant Organization: Smith Consulting Ltd
Registrant Email: john@smithconsulting.com
Registrant Country: GB
Name Server: NS1.DIGITALOCEAN.COM
Name Server: NS2.DIGITALOCEAN.COM`

describe('parseWhois', () => {
  describe('standard WHOIS (IANA/example)', () => {
    const result = parseWhois('example.com', SAMPLE_WHOIS)

    it('extracts domain', () => {
      expect(result.domain).toBe('example.com')
    })

    it('extracts registrar', () => {
      expect(result.registrar).toContain('RESERVED-Internet Assigned Numbers Authority')
    })

    it('extracts creation date', () => {
      expect(result.createdDate).toContain('1995')
    })

    it('extracts expiry date', () => {
      expect(result.expiresDate).toContain('2025')
    })

    it('extracts nameservers', () => {
      expect(result.nameservers).toContain('a.iana-servers.net')
      expect(result.nameservers).toContain('b.iana-servers.net')
    })

    it('extracts status flags', () => {
      expect(result.status.length).toBeGreaterThan(0)
    })

    it('not privacy protected', () => {
      expect(result.isPrivacyProtected).toBe(false)
    })
  })

  describe('GDPR-redacted WHOIS', () => {
    const result = parseWhois('competitor.co.uk', GDPR_WHOIS)

    it('detects privacy protection', () => {
      expect(result.isPrivacyProtected).toBe(true)
    })

    it('registrant name is redacted', () => {
      expect(result.registrantName).toContain('Redacted')
    })

    it('registrant org is privacy service', () => {
      expect(result.registrantOrg).toContain('Privacy')
    })

    it('still extracts registrar', () => {
      expect(result.registrar).toContain('NameCheap')
    })

    it('extracts nameservers', () => {
      expect(result.nameservers.length).toBe(3)
      expect(result.nameservers[0]).toContain('digitalocean')
    })

    it('extracts creation date', () => {
      expect(result.createdDate).toContain('2023')
    })
  })

  describe('visible registrant WHOIS', () => {
    const result = parseWhois('smallbusiness.com', VISIBLE_WHOIS)

    it('extracts registrant name', () => {
      expect(result.registrantName).toBe('John Smith')
    })

    it('extracts registrant org', () => {
      expect(result.registrantOrg).toBe('Smith Consulting Ltd')
    })

    it('extracts registrant email', () => {
      expect(result.registrantEmail).toBe('john@smithconsulting.com')
    })

    it('extracts registrant country', () => {
      expect(result.registrantCountry).toBe('GB')
    })

    it('not privacy protected', () => {
      expect(result.isPrivacyProtected).toBe(false)
    })
  })

  describe('edge cases', () => {
    it('handles empty WHOIS response', () => {
      const result = parseWhois('empty.com', '')
      expect(result.registrar).toBeNull()
      expect(result.nameservers.length).toBe(0)
      expect(result.isPrivacyProtected).toBe(false)
    })

    it('preserves raw text', () => {
      const result = parseWhois('test.com', SAMPLE_WHOIS)
      expect(result.rawText).toBe(SAMPLE_WHOIS)
    })

    it('deduplicates nameservers', () => {
      const dupeWhois = `Name Server: NS1.EXAMPLE.COM
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM`
      const result = parseWhois('test.com', dupeWhois)
      expect(result.nameservers.length).toBe(2)
    })
  })
})
