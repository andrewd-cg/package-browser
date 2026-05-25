# package-browser

A simple tool to compare package versions across public registries and the **Chainguard registry** (`libraries.cgr.dev`). Supports npm, Maven, and PyPI — for a single package or a whole manifest at once.

Enter a package name (or Maven `groupId:artifactId`) and get a side-by-side table showing which versions are available in each registry, whether they were built by Chainguard or mirrored from upstream, and when each version was published. Or use the **bulk check** tab to drop in a `package.json` / `requirements.txt` / lockfile and see Chainguard coverage across every dependency at once.

## Features

- Four tabs: **npm**, **maven**, **pypi**, **bulk check**
- Side-by-side version comparison: public registry vs Chainguard
- Built vs Secure Mirror badge per Chainguard version
- Coverage summary: % of versions in Chainguard, broken down by Built vs Mirrored
- Publish date + days ago for each version
- Pre-release versions hidden by default
- Limit to 50 most recent versions by default
- Copy results as formatted plain text for sharing in Slack or a text editor
- Bulk check: paste or drag-and-drop a manifest (`package.json`, `package-lock.json`, `yarn.lock`, `requirements.txt`, `poetry.lock`) to check Chainguard coverage for every dependency in one pass; click any row to drill into the per-package view
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

## How it works

The browser cannot talk to `libraries.cgr.dev` directly due to CORS restrictions, so all Chainguard registry calls are routed through a local proxy server (`server.js`). Public registry calls are made directly from the browser.

```
Browser → GET /api/cgr/<pkg>                   → server.js → libraries.cgr.dev/javascript (Basic Auth)
Browser → GET /api/cgr-java?group=..&artifact= → server.js → libraries.cgr.dev/java (Basic Auth)
Browser → GET /api/cgr-python/simple/<pkg>/    → server.js → libraries.cgr.dev/python/simple (Basic Auth)
Browser → GET /api/maven-metadata              → server.js → repo1.maven.org (public)
Browser → GET /api/maven-timestamps            → server.js → search.maven.org (public, CORS blocked)

Browser → GET registry.npmjs.org/<pkg>         (direct, CORS supported)
Browser → GET pypi.org/pypi/<pkg>/json         (direct, CORS supported)
```
