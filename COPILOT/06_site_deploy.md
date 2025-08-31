# Task 06 — Site Deploy & Samples (Cloudflare Pages)
**Prompt:**
Wire `carnot-site/` to Cloudflare Pages. Publish sample attestation & PCAP walkthrough under `docs/samples/`. Link from homepage.

**Acceptance:**
- Site live; links work; WORKLOG updated.

---
Progress:
- [x] Static site scaffold created (`carnot-site/index.html`).
- [x] Sample attestation JSON & Markdown added (`docs/samples/`).
- [x] PCAP walkthrough HTML added (`docs/samples/pcap_walkthrough.html`).
- [x] Deployment workflow added (`.github/workflows/site.yml`).
- [x] WORKLOG updated.
- [ ] Cloudflare secrets added & first deploy succeeded.

Required GitHub Secrets:
- `CLOUDFLARE_API_TOKEN` (Pages write token with Pages:Edit).
- `CLOUDFLARE_ACCOUNT_ID` (account identifier from Cloudflare Dashboard > Workers & Pages > Overview).

After adding secrets, push any change under `carnot-site/` to trigger deployment.
