# package-browser

A simple tool to compare package versions across public registries and the **Chainguard registry** (`libraries.cgr.dev`). Supports npm, Maven, and PyPI — for a single package, a whole manifest, or browsing the Chainguard malware feed.

Enter a package name (or Maven `groupId:artifactId`) and get a side-by-side table showing which versions are available in each registry, whether they were built by Chainguard or mirrored from upstream, and when each version was published. Use the **bulk check** tab to drop in a `package.json` / `requirements.txt` / lockfile and see Chainguard coverage across every dependency at once. Use the **malware** tab to browse, filter, and visualize the Chainguard malicious-package dataset (synced and cached locally to SQLite).

## Features

- Five tabs: **npm**, **maven**, **pypi**, **bulk check**, **malware**
- Side-by-side version comparison: public registry vs Chainguard
- Built vs Secure Mirror badge per Chainguard version
- Coverage summary: % of versions in Chainguard, broken down by Built vs Mirrored
- Publish date + days ago for each version
- Pre-release versions hidden by default
- Limit to 50 most recent versions by default
- Copy results as formatted plain text for sharing in Slack or a text editor
- Bulk check: paste or drag-and-drop a manifest (`package.json`, `package-lock.json`, `yarn.lock`, `requirements.txt`, `poetry.lock`) to check Chainguard coverage for every dependency in one pass; click any row to drill into the per-package view
- Malware tab: local SQLite cache of Chainguard's malicious-package dataset (~117k+ entries) with a per-day timeline bar chart, server-side filtering by package name / version / source / reason / date range, and incremental sync (only fetches new entries since the last `MAX(blocked_at)`); click any bar in the chart to drill into that day
- Malware badges on the npm tab: versions (or whole packages) flagged in the malware DB show a red `MALWARE` badge next to `latest` / `scripts`, with a hover tooltip showing source, block date, and reasons
- Credentials stored per ecosystem in browser `localStorage` — never sent anywhere except the local proxy

## Start

### Option 1: Docker (recommended)

```bash
docker run -p 3000:3000 ghcr.io/andrewd-cg/package-browser:latest
```

Or with Docker Compose:

```bash
docker compose up
```

Then open [http://localhost:3000](http://localhost:3000).

The bundled `docker-compose.yml` includes an `init-data` sidecar that chowns the `./data` bind mount to the chainguard `nonroot` user (uid 65532) once on every `up`, and a volume mount so the malware SQLite cache (`./data/malware.db`) persists across container restarts. Override the DB location with the `MALWARE_DB_PATH` env var (default: `./malware.db` next to the server).

### Option 2: Bun

Requires [Bun](https://bun.sh):

```bash
curl -fsSL https://bun.sh/install | bash
./start.sh
```

Then open [http://localhost:3000](http://localhost:3000).

## Configuration

Click the **gear icon** (top right) to open the settings panel. Each ecosystem has its own username and password. **Save** stores and tests them; **Test** re-checks the current values without saving. All three tokens are also tested on page load — if any fail (e.g. expired pull token), a red dot appears on the gear icon and the failure reason is shown in the settings panel.

To get credentials, run one of the following depending on which registry you need:

```bash
# npm / JavaScript
chainctl auth pull-token --repository=javascript --parent=andrewd.dev --ttl=8760h

# Maven / Java
chainctl auth pull-token --repository=java --parent=andrewd.dev --ttl=8760h

# PyPI / Python
chainctl auth pull-token --repository=python --parent=andrewd.dev --ttl=8760h
```

Copy the username and password from the output into the corresponding fields in the settings panel.

## Malware tab

The malware tab caches Chainguard's malicious-package dataset locally to SQLite so the UI can filter and visualize ~117k+ entries without re-paginating the upstream feed every time.

- **Update Malware DB** — incremental sync: fetches only entries with `blocked_at > MAX(blocked_at)` in the local DB. Cheap to run repeatedly.
- **Full re-sync** — drops the `since` floor to 2026-01-01 and refetches the whole window. Use this for first-time sync, or after a long gap. Takes ~5 minutes for 117k rows at `page_size=500`.
- **Source filter** — defaults to `chainguard` (Sentinel detections, ~3.5k rows). Switch to **All sources** to also include OSV advisories (the bulk of the dataset) and manually curated entries.
- **Timeline chart** — bars per UTC day, click any bar to set both date filters to that day. The axis adapts to the range (daily labels for ≤14 days, every-other-day for ≤30, weekly for ≤60, monthly otherwise). The `max:` label in the top-left shows the peak count.
- **Reason filter** — facet dropdown populated from the cache. Individual `MAL-YYYY-N` advisory IDs are collapsed into one `MAL-ID*` bucket; selecting it filters to any row tagged with any MAL advisory.

The cache uses the existing `javascript` Chainguard pull-token (Basic auth) — there's no separate auth setup. Auth is tested on page load (red dot on the gear icon if anything fails).

## How it works

The browser cannot talk to `libraries.cgr.dev` directly due to CORS restrictions, so all Chainguard registry calls are routed through a local proxy server (`server.js`). Public registry calls are made directly from the browser.

```
Browser → GET /api/cgr/<pkg>                       → server.js → libraries.cgr.dev/javascript (Basic Auth)
Browser → GET /api/cgr-java?group=..&artifact=     → server.js → libraries.cgr.dev/java (Basic Auth)
Browser → GET /api/cgr-python/simple/<pkg>/        → server.js → libraries.cgr.dev/python/simple (Basic Auth)
Browser → GET /api/maven-metadata                  → server.js → repo1.maven.org (public)
Browser → GET /api/maven-timestamps                → server.js → search.maven.org (public, CORS blocked)

Malware cache (SQLite at $MALWARE_DB_PATH):
Browser → POST /api/cgr-malware/sync               → server.js streams NDJSON progress while paginating
                                                     libraries.cgr.dev/javascript/-/api/malware (Basic Auth, page_size=500)
Browser → GET  /api/cgr-malware/status             → server.js (local DB)
Browser → GET  /api/cgr-malware/search?...         → server.js (local DB; filtered + paginated)
Browser → GET  /api/cgr-malware/histogram?...      → server.js (local DB; per-day GROUP BY)
Browser → GET  /api/cgr-malware/reasons            → server.js (local DB; distinct reasons + counts)
Browser → GET  /api/cgr-malware/check?package=...  → server.js (local DB; used by npm tab to badge versions)

Browser → GET registry.npmjs.org/<pkg>             (direct, CORS supported)
Browser → GET pypi.org/pypi/<pkg>/json             (direct, CORS supported)
```
