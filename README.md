# Linkism Site

> 🌐 **Official website for the Linkism Protocol Suite**  
> [linkism.org](https://linkism.org) — A persistent identity layer for the world’s UI

---

## Overview

This repository powers [**linkism.org**](https://linkism.org), the canonical reference site for the Linkism Protocol — a specification suite for resilient, cryptographically-verifiable UI element selectors.

The site renders:

- 📘 Full RFC Suite:  
  - [RFC-001] LID URI Specification  
  - [RFC-002] SCR Bundle Format  
  - [RFC-003] Resolution Protocol  
  - [BCP-001] Deployment Guidelines

- 🧪 Reference Implementation  
- 🛠 Quickstart CLI Docs  
- 📄 Downloadable PDFs  
- 🧵 Future discussions + integration guides

---

## Tech Stack

- **Framework**: [Next.js](https://nextjs.org/) 15  
- **Styling**: Tailwind CSS + MDX  
- **Deployment**: [Vercel](https://vercel.com/)  
- **PDF Output**: RFCs rendered server-side via MD-to-PDF pipeline  
- **Dark Mode**: System preference + toggle-ready  

---

## Local Development

```bash
git clone https://github.com/linkism/linkism-site.git
cd linkism-site
npm install
npm run dev

Then visit http://localhost:3000 in your browser.


---

File Structure

.
├── src/
│   ├── app/             # Next.js 15 routing
│   ├── components/      # Custom React components
│   ├── data/            # RFC content and metadata
│   └── styles/          # Tailwind config and globals
├── public/              # Static PDFs, images, favicon
├── linkism-protocol-suite.pdf
└── README.md


---

Deployment

Deployment is handled via Vercel:

Production: pushed to main → linkism.org

Preview: PRs automatically get Vercel preview URLs


No manual deploy steps needed if connected to GitHub.


---

Contributing

All contributions to the site layout, component styling, or RFC presentation can be submitted as pull requests.

RFC content lives in linkism-protocol and is imported as Markdown from there.


---

License

All content is published under CC BY-SA 4.0
Open specification. Royalty-free. Protocol-first.


---

Maintainer

Joel D. Trout II
Author of the Linkism Protocol
@ziolndr · linkism.org
