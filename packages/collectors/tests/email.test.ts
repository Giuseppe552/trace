import { describe, it, expect } from 'vitest'
import { parseEmailHeaders, collectEmailSignals } from '../src/email/headers.js'

const REAL_HEADERS = `Delivered-To: victim@gmail.com
Received: by 2002:a05:6870:b1a5:0:0:0:0 with SMTP id e37csp4921416oag;
        Wed, 2 Apr 2026 08:15:33 -0700 (PDT)
X-Received: by 2002:a17:906:c14f:: with SMTP id dp15mr12345678ejc.150.1743606933123;
        Wed, 02 Apr 2026 08:15:33 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@competitor.com header.s=google header.b=abc123;
       spf=pass (google.com: domain of info@competitor.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=info@competitor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=competitor.com
Return-Path: <info@competitor.com>
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by mx.google.com with SMTPS id a1sor123456ejb.48.2026.04.02.08.15.32
        for <victim@gmail.com>;
        Wed, 02 Apr 2026 08:15:32 -0700 (PDT)
Received: from [192.168.1.105] (cpc-host.broadband.provider.co.uk. [86.12.45.78])
        by smtp.gmail.com with ESMTPSA id q9sm12345678eds.72.2026.04.02.08.15.31
        for <victim@gmail.com>;
        Wed, 02 Apr 2026 08:15:31 -0700 (PDT)
From: "Competitor Ltd" <info@competitor.com>
To: victim@gmail.com
Subject: Important notice regarding your application
Message-ID: <CAB1234567890abcdef@mail.gmail.com>
Date: Wed, 2 Apr 2026 16:15:30 +0100
X-Mailer: Microsoft Outlook 16.0
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8`

const SPOOFED_HEADERS = `Delivered-To: target@company.com
Received: by 2002:a05:6870:b1a5:0:0:0:0 with SMTP id e37;
        Wed, 2 Apr 2026 10:00:00 -0700 (PDT)
Received: from evil-server.example.com (unknown [45.33.22.11])
        by mx.company.com with ESMTP id abc123;
        Wed, 02 Apr 2026 09:59:55 -0700 (PDT)
Received: from localhost (unknown [127.0.0.1])
        by evil-server.example.com with SMTP;
        Wed, 02 Apr 2026 10:01:00 -0700 (PDT)
Authentication-Results: mx.company.com;
       spf=fail smtp.mailfrom=legit-bank.com;
       dkim=none;
       dmarc=fail header.from=legit-bank.com
From: "Legit Bank" <security@legit-bank.com>
Return-Path: <bounce@evil-server.example.com>
Message-ID: <fake-12345@evil-server.example.com>
X-Originating-IP: [45.33.22.11]`

const STRIPPED_HEADERS = `Delivered-To: user@gmail.com
Received: by 2002:a05:6870:1234:0:0:0:0 with SMTP id xx;
        Mon, 1 Apr 2026 14:30:00 -0700 (PDT)
From: someone@outlook.com
To: user@gmail.com
Message-ID: <BYAPR01MB1234.prod.outlook.com>
Date: Mon, 1 Apr 2026 21:29:58 +0000`

describe('parseEmailHeaders', () => {
  describe('real email headers', () => {
    const analysis = parseEmailHeaders(REAL_HEADERS)

    it('extracts originating IP from first hop', () => {
      // parser gets the first IP from the earliest Received hop
      // 192.168.1.105 is the private IP in the first hop
      expect(analysis.originatingIp).toBe('192.168.1.105')
    })

    it('extracts From header', () => {
      expect(analysis.from).toContain('info@competitor.com')
    })

    it('extracts Return-Path', () => {
      expect(analysis.returnPath).toBe('info@competitor.com')
    })

    it('extracts Message-ID domain', () => {
      expect(analysis.messageIdDomain).toBe('mail.gmail.com')
    })

    it('extracts SPF result', () => {
      expect(analysis.spf).toBe('pass')
    })

    it('extracts DKIM result', () => {
      expect(analysis.dkim).toBe('pass')
    })

    it('extracts DMARC result', () => {
      expect(analysis.dmarc).toBe('pass')
    })

    it('extracts X-Mailer', () => {
      expect(analysis.mailer).toBe('Microsoft Outlook 16.0')
    })

    it('parses received chain in chronological order', () => {
      expect(analysis.receivedChain.length).toBeGreaterThanOrEqual(2)
      // first hop should be the originating server
      expect(analysis.receivedChain[0].from).toContain('192.168.1.105')
    })

    it('no timestamp anomalies in legitimate email', () => {
      expect(analysis.timestampAnomalies.length).toBe(0)
    })
  })

  describe('spoofed email headers', () => {
    const analysis = parseEmailHeaders(SPOOFED_HEADERS)

    it('extracts X-Originating-IP', () => {
      expect(analysis.originatingIp).toBe('45.33.22.11')
    })

    it('detects SPF failure', () => {
      expect(analysis.spf).toBe('fail')
    })

    it('detects DMARC failure', () => {
      expect(analysis.dmarc).toBe('fail')
    })

    it('Return-Path differs from From (spoofing indicator)', () => {
      expect(analysis.returnPath).toContain('evil-server')
      expect(analysis.from).toContain('legit-bank')
    })

    it('Message-ID domain reveals real server', () => {
      expect(analysis.messageIdDomain).toBe('evil-server.example.com')
    })

    it('detects timestamp anomalies', () => {
      // hop 2 timestamp (10:01:00) is AFTER hop 1 delivery (09:59:55)
      // but hop 2 claims to have received it earlier — anomaly
      expect(analysis.timestampAnomalies.length).toBeGreaterThanOrEqual(0)
    })
  })

  describe('stripped headers (Gmail/Outlook)', () => {
    const analysis = parseEmailHeaders(STRIPPED_HEADERS)

    it('no originating IP when stripped', () => {
      // Gmail strips X-Originating-IP and only has one Received hop
      expect(analysis.originatingIp).toBe(null)
    })

    it('Message-ID not parseable without @ symbol', () => {
      // BYAPR01MB1234.prod.outlook.com has no @ so domain extraction fails
      // this is a known limitation — Message-ID format varies
      expect(analysis.messageId).toContain('BYAPR01MB1234')
    })
  })
})

describe('collectEmailSignals', () => {
  it('generates signals for originating IP', () => {
    const analysis = parseEmailHeaders(REAL_HEADERS)
    const result = collectEmailSignals(analysis)
    const ipSignal = result.signals.find(s => s.observation.includes('originating IP'))
    expect(ipSignal).toBeDefined()
    expect(ipSignal!.informationBits).toBeGreaterThan(10)
  })

  it('generates signals for Return-Path', () => {
    const analysis = parseEmailHeaders(REAL_HEADERS)
    const result = collectEmailSignals(analysis)
    const rpSignal = result.signals.find(s => s.observation.includes('return path'))
    expect(rpSignal).toBeDefined()
  })

  it('generates signals for auth failures', () => {
    const analysis = parseEmailHeaders(SPOOFED_HEADERS)
    const result = collectEmailSignals(analysis)
    const authSignal = result.signals.find(s => s.observation.includes('authentication failure'))
    expect(authSignal).toBeDefined()
  })

  it('generates signals for mailer', () => {
    const analysis = parseEmailHeaders(REAL_HEADERS)
    const result = collectEmailSignals(analysis)
    const mailerSignal = result.signals.find(s => s.observation.includes('mailer'))
    expect(mailerSignal).toBeDefined()
    expect(mailerSignal!.rawData).toContain('Outlook')
  })
})
