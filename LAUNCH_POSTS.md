=================================================================
INDIE HACKERS POST
=================================================================

Title: I built a security event monitoring tool for startups — validating before launch

Body:

Hey IH,

I've been building LogSentry over the past few weeks — a security event dashboard aimed at small startups and dev teams who can't justify $300/month for Datadog or Splunk.

**The problem I kept running into:**
Every startup I've talked to either has no security monitoring at all, or is paying enterprise prices for tools built for 500-person companies. There's a massive gap in the middle.

**What LogSentry does:**
- Ingest server logs via file upload or API
- Automatically classify events (failed logins, port scans, errors, warnings)
- Send real-time email alerts for high-severity events
- Clean dashboard showing exactly what's happening on your servers

**Pricing (usage-based, startup-friendly):**
- Free: 500 events/month
- Starter: $29/month — 50,000 events
- Pro: $79/month — unlimited

**Where I'm at:**
The product is built and working locally. Before I spend money on hosting and infrastructure, I want to make sure people actually want this. So I'm collecting waitlist signups first.

If you're a founder or developer who's ever thought "I should probably be monitoring my server logs but it's too expensive/complicated" — that's exactly who I built this for.

Waitlist: [security-event-dashboard-production.up.railway.app]

Happy to answer any questions about the build or the idea. Brutal feedback welcome — I'd rather know now if this is a bad idea than after I've spent 3 months marketing it.

---

**What I'm most unsure about:**
- Is $29/month the right entry price, or too high/low?
- Would you pay for this, or just use a free open-source alternative?


=================================================================
HACKER NEWS — SHOW HN POST
=================================================================

Title: Show HN: LogSentry – Security event monitoring for startups ($29/mo vs $300/mo alternatives)

Body:

I built LogSentry after noticing most small startups either have zero security monitoring or are paying enterprise prices for tools like Datadog, Splunk, or Sumo Logic.

LogSentry lets you ingest server logs (via file upload or API), automatically classifies events (failed logins, port scans, anomalies), and sends real-time email alerts when something high-severity is detected.

Tech stack: Flask, PostgreSQL, Stripe for billing, Resend for email alerts.

Pricing: Free (500 events/month) → Starter ($29/month, 50k events) → Pro ($79/month, unlimited).

Still pre-launch — collecting waitlist signups before deploying. Wanted to share here to get early feedback from people who'd actually use something like this.

Waitlist/landing page: [YOUR LANDING PAGE URL]

Happy to answer questions about the build or discuss whether this is a solved problem.


=================================================================
REDDIT — r/SaaS or r/startups
=================================================================

Title: Pre-launch: I built a security monitoring tool for startups — is $29/month too expensive?

Body:

Been building LogSentry for a few weeks — a security event dashboard aimed at small startups.

The gap I saw: enterprise security tools (Datadog, Splunk, Sumo Logic) cost $200-500+/month. Most small startups either skip monitoring entirely or cobble something together with grep and cron jobs.

LogSentry sits in the middle:
• Upload server logs or push via API
• Auto-classifies failed logins, port scans, errors
• Real-time email alerts for high-severity events  
• Clean dashboard, no enterprise bloat

Pricing:
• Free — 500 events/month
• Starter — $29/month, 50k events
• Pro — $79/month, unlimited

Pre-launch right now, collecting waitlist signups before deploying on real infrastructure.

**My question for this community:** Is $29/month a reasonable entry price for a tool like this? I want to make sure I'm not undercharging (or overcharging) before I start marketing.

Landing page: [YOUR LANDING PAGE URL]

Honest feedback appreciated — especially if you think this is a bad idea or already solved by something free.