# TruffleHog Explorer 🕵️‍♂️

Welcome to [**TruffleHog Explorer**](gonzosint.github.io/trufflehog-explorer/), a user-friendly web-based tool to visualize and analyze data extracted using [TruffleHog](https://github.com/trufflesecurity/trufflehog). TruffleHog is one of the most powerful secrets discovery, classification, validation, and analysis open source tool. In this context, a secret refers to a credential a machine uses to authenticate itself to another machine. This includes API keys, database passwords, private encryption keys, and more.

With an improved UI/UX, powerful filtering options, and export capabilities, this tool helps security professionals efficiently review potential secrets and credentials found in their repositories.

> ⚠️ This dashboard has been tested only with GitHub TruffleHog JSON outputs. Expect updates soon to support additional formats and platforms.

You can use online version here: [**TruffleHog Explorer**](gonzosint.github.io/trufflehog-explorer/)

![TruffleHog Explorer Screenshot](static/screenshot.png)

---

## 🚀 Features

- **Handles noisy scans:** built for full scans run without verification, where most findings are false positives.
- **Pattern filters on every field:** detector, file path, repository, secret value, author, commit, decoder, extra data and source file. Each field supports wildcards, regex and exclusions (see [Filter syntax](#-filter-syntax)).
- **Bulk pruning with reasons:** prune everything matching the current filters. Each pruned finding keeps the reason it was pruned, and you can restore findings at any time. TruffleHog-verified and confirmed findings are protected from bulk pruning.
- **Reusable prune rules:** save the current filters as a named rule, apply one or all rules to a new scan, and export or import rules as JSON.
- **Noise hotspots:** a ranked list of detector + file name pairs with the most kept findings (for example `Github` in `yarn.lock`), each with one-click Filter and Prune.
- **Group by secret:** one card per unique detector + secret value. Confirm or prune every occurrence at once.
- **Cross-reference a verified scan:** load a full scan, then add a verified-only scan. Matching locations are merged and marked verified.
- **Versions:** save the result of a review pass as downloadable kept and pruned NDJSON files plus a review file.
- **Exports:** kept, pruned, filtered or verified/confirmed findings as NDJSON (TruffleHog format, re-loadable), a JSON array, or CSV (secrets masked).
- **Secrets masked by default:** reveal or copy a secret on each card, or reveal them all at once.
- **Review UX:** active filter chips, helpful empty states, page size selector, statistics (kept, pruned, confirmed, unique secrets, verification errors) and the `/` shortcut to jump to the filters.

---
## 📥 Installation & Usage


### 1. Clone the Repository
```bash
$ git clone https://github.com/GONZOsint/trufflehog-explorer.git
$ cd trufflehog-explorer
```

### 2. Open the `index.html`
Simply open the `index.html` file in your preferred web browser.

```bash
$ open index.html
```

---

## 📂 How to Use

### Recommended workflow

1. **Run TruffleHog twice** (example for a GitHub org):
   ```bash
   trufflehog github --org=<org> --json --no-verification > all_verify_off.json
   trufflehog github --org=<org> --json --results=verified > all_only_verified.json
   ```
2. **Load the full scan** in **Load Data**.
3. **Cross-reference verified results:** tick **Add to current data (cross-reference)** and load the verified-only scan. Matching findings are marked verified, which also protects them from bulk pruning.
4. **Prune the noise:**
   - Start with **Noise hotspots** and use **Prune** on detector + file pairs that are clearly false positives (lockfiles, test fixtures and so on).
   - Or build filters yourself (for example File path `*.lock`), check the count, then click **Prune Filtered**. You are shown the number of findings to prune and asked for a reason.
   - Use **Save Filters as Rule** to reuse the filters on the next scan.
5. **Review what's left:** switch to **Group by Secret** to review each unique secret once, and confirm true positives.
6. **Save a version:** click **Save Version…** to download:
   - `*_kept.ndjson`: the findings that remain, in TruffleHog format
   - `*_pruned.ndjson`: what was removed
   - `*_review.json`: decisions and rules, without secrets

   Load the kept file later to continue from the pruned result, or load the original scan together with the review file to restore every decision.

### 🔎 Filter syntax

| Pattern | Meaning |
| --- | --- |
| `terraform` | Plain text matches anywhere in the value |
| `*.lock`, `tok_?` | `*` matches any characters, `?` matches one character; wildcard patterns must match the whole value |
| `/^AKIA[0-9A-Z]{16}$/` | Regular expression |
| `!*.lock` | Exclude matches (works with any pattern type) |
| `AWS, Azure*` | Comma-separated patterns: the value must match any include pattern and no exclude pattern |

All patterns are case-insensitive. Filters on different fields are combined (all must match). The **Extra data** field matches `key=value` pairs from TruffleHog's `ExtraData`, for example `token_type=*`.

### Review state and privacy

- Everything runs in your browser; no data is uploaded anywhere.
- Prune and confirm decisions, rules and version summaries are saved in the browser's `localStorage`. Findings and secrets are never stored there.
- Review files and CSV exports contain no secret values. NDJSON and JSON exports keep the original TruffleHog records, including secrets, so handle them like the scan output.
- If you keep scan output inside this repository, put it in `data/`, which is git-ignored.

---

## 🧪 Development

The app is static with no build step. Core logic lives in `js/core.js` (shared by the browser and the tests) and the UI in `js/app.js`. Run the unit tests with Node.js 18+:

```bash
$ npm test
```

---
**Happy Securing! 🔒**

