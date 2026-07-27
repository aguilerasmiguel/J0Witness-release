# J0Witness

![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)
![CGO](https://img.shields.io/badge/CGO-free-2ea44f)
![Binary](https://img.shields.io/badge/binary-single%20static-2ea44f)
![Network](https://img.shields.io/badge/network-offline%20by%20default-4c9be8)
![Build](https://img.shields.io/badge/build-reproducible-2ea44f)
![Determinism](https://img.shields.io/badge/output-deterministic-2ea44f)
![Platform](https://img.shields.io/badge/platform-linux%20amd64%20%7C%20arm64-lightgrey)
![Reports](https://img.shields.io/badge/reports-json%20%7C%20text%20%7C%20pdf%20%7C%20sarif-informational)
![i18n](https://img.shields.io/badge/i18n-en%20%7C%20es-informational)
![License](https://img.shields.io/badge/license-MIT-2ea44f)

> **Read this in other languages:** [EspaÃ±ol](README.es.md)

**J0Witness is an offline integrity and forensic analyzer for Joomla installations.**

It determines â without the site being live, and without needing a prior baseline
of your own â how a Joomla installation on disk differs from the original vendor
distribution, and presents those differences with enough evidence and provenance
for a human to decide whether a compromise occurred.

> **J0Witness observes and testifies. It does not repair, clean, or restore.**

---

## Why it exists

Most "is my site hacked?" tooling either needs the site running, phones home, or
mutates the very evidence it is inspecting. J0Witness is built the opposite way:

- **Offline and self-contained.** A single static binary. No PHP runtime, no
  database, no network by default. Copy it to the host and run it.
- **The analyzed tree is evidence â never written to.** J0Witness only reads.
- **It never executes the analyzed code.** All PHP/config analysis is static text
  analysis; the tree is never run.
- **Deterministic and reproducible.** The same (tree, baseline, binary, flags)
  produces byte-identical output, and the binary itself is a reproducible build â
  both properties matter when the report is used as evidence.
- **A false positive is treated as a severe defect.** The engine degrades toward
  silence rather than crying wolf; every finding is meant to be actionable.

## What it does

J0Witness composes independent analysis layers, each reading the already-captured
evidence and contributing observations. Verdicts (findings) are **derived by
query** from those observations â never stored as primary truth â so a report can
be re-rendered from a persisted scan without re-touching the tree.

| Layer | What it does | Rules |
|------|---------------|-------|
| **L0** acquire | Deterministic inventory: hash, metadata, size. Read-only. | â |
| **L1** fingerprint | Fuzzy hashing (TLSH) to pair modified files with their original. | â |
| **L2** core-diff | Diff against the official Joomla distribution: added / modified / deleted core files. | `J0W-CORE-*` |
| **L3** ext-map | Discovers third-party extensions by manifest and attributes each file to its declaring extension. | `J0W-EXT-*`, `J0W-LAYOUT-001` |
| **L4** code-scan | Static PHP content analysis (never executes): webshells, obfuscation, execution loaders. | `J0W-CODE-*` |
| **L5** conf-scan | Dangerous directives in `.htaccess` / `.user.ini` / `web.config`. | `J0W-CONFIG-*` |
| **L6** timeline | Temporal corroboration anchored on ctime (under the declared threat model). | `J0W-TIME-001` |
| **L7** db-scan | Correlation with the site's database via a provided `mysqldump` (offline, never executed). | `J0W-DB-*` |

Plus:

- **Scan-to-scan drift** (`j0witness diff`): compares two persisted scans of the
  same site â the monitoring / incident-response question, *"what changed since the
  last known-good scan?"*
- **Baseline verification at scan time**: the embedded catalog is the single root
  of trust; the stored baseline and cached official package are re-verified against
  it before the diff trusts them, and the scan hard-refuses (`BASELINE_UNTRUSTED`)
  on tampering.
- **Four report projections** from one canonical JSON: `json` Â· `text` Â· `pdf` Â·
  `sarif` (for CI / code-scanning integration).
- **Bilingual reports**: `--language en|es`.
- **False-positive suppression**: a declarative exclusions file where the reason is
  mandatory and every suppression is echoed back in the report.

## Quick start

```sh
# 1. Ingest the official baseline once (offline: download the package separately).
j0witness baseline add Joomla_5.1.4-Stable-Full_Package.zip
#    Or, with explicitly authorized network:
#    j0witness baseline fetch 5.1.4 --allow-network

# 2. Scan. stdout = canonical JSON report; stderr = progress.
j0witness scan /var/www/mysite > report.json

# Human-readable:
j0witness scan /var/www/mysite --format text
j0witness scan /var/www/mysite --format pdf > report.pdf

# 3. Correlate with the database (offline; the dump is parsed, never executed):
j0witness scan /var/www/mysite --db dump.sql --format text

# 4. Monitoring / IR â what changed since the last scan:
j0witness runs /var/www/mysite          # list persisted scans
j0witness diff /var/www/mysite          # drift between the two most recent

# 5. Re-render a persisted scan without re-touching the tree:
j0witness report ~/.local/state/j0witness --format sarif
```

Build instructions: **[docs/BUILD.md](docs/BUILD.md)**.

## Exit codes (stable contract)

`0` clean Â· `1` findings â¥ medium Â· `2` usage error Â· `3` preflight failed Â·
`4` baseline unavailable Â· `5` multiple installations Â· `6/7` version unsupported /
inconclusive Â· `8` baseline untrusted (stored baseline does not match the embedded
catalog) Â· `10` internal error.

## Scope and honest limitations

J0Witness is deliberately narrow, and it is more useful when you know exactly what
it can and cannot answer.

**The question it answers well:** *"Does the on-disk tree match the known-good
vendor distribution plus the declared third-party extensions â and if not, where,
and with what evidence?"*

**What it detects:** added / modified / deleted core files; webshell and obfuscation
patterns in PHP (heuristic, static); undeclared executables hiding inside a
legitimately-installed extension; dangerous server-config directives; structural
timestomping (`mtime > ctime`); database-state anomalies when you provide a dump;
and drift between two scans of the same site.

**What it does *not* do â read this before relying on it:**

- **It does not repair, clean, quarantine, or restore.** It observes and testifies.
- **Absence of findings is not proof of a clean site.** It is evidence about the
  disk, bounded by the layers below.
- **It is blind to compromise that lives only outside the filesystem** â purely
  in-database persistence (unless you supply a `mysqldump`), in-memory/runtime
  implants, or malicious state in external services. There is no live process,
  network, or memory inspection.
- **Static PHP analysis is heuristic.** It is tuned to minimize false positives,
  which means it can miss novel, heavily-obfuscated, or logic-only backdoors. It is
  a signal, not a proof of maliciousness or of safety.
- **The database layer never connects to a live database.** It correlates an
  offline `mysqldump` you provide; if the dump does not correspond to the disk, the
  layer degrades and declares the mismatch rather than emitting noise.
- **Its ground truth is the official distribution and the embedded catalog.** Files
  the vendor does not ship (third-party extension internals, uploads, user content)
  are attributed and contextualized, not deeply verified beyond an extension's
  official-package hash when it is cached. A supply-chain compromise *upstream* of
  the baseline you feed it is outside its reach (baseline integrity is now verified
  against the embedded catalog at scan time â see L7 / `BASELINE_UNTRUSTED`).
- **The temporal layer trusts ctime under a declared threat model** (an attacker
  with www-data privileges, no root). A root-level attacker who can rewrite ctime
  defeats it; backdating (`mtime << ctime`) is explicitly a non-goal because it is
  indistinguishable from a normally-extracted archive.
- **It is one evidence source, not a full IR/EDR/AV.** Treat it as forensic
  corroboration, not as a verdict engine.

**Declared threat model (primary):** an attacker operating with the web server's
privileges (`www-data`) and no root. Under that model ctime is the reliable
temporal anchor. This assumption is stated so the reader can judge where it holds.

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)** ([EspaÃ±ol](docs/ARQUITECTURA.md)) â layers, data flow, trust model, diagrams.
- **[Build](docs/BUILD.md)** â compiling the single static binary and the reproducibility gate.
- **[Roadmap](docs/ROADMAP.md)** â planned and possible future work.
- **[Source](src/)** â the full Go source tree.

## License

This project is released under the MIT License — see [LICENSE](LICENSE).
