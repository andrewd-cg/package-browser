// Run with: ~/.bun/bin/bun server.js
import { createPublicKey, verify as cryptoVerify, X509Certificate } from 'crypto';
import { Database } from 'bun:sqlite';
const htmlPath = new URL('./index.html', import.meta.url);

// ── Malware cache (SQLite) ────────────────────────────────────────────────────
const DB_PATH = process.env.MALWARE_DB_PATH || './malware.db';
const db = new Database(DB_PATH);
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS malware (
    package_name TEXT NOT NULL,
    version     TEXT,
    scope       TEXT,
    malid       TEXT,
    source      TEXT,
    blocked_at  TEXT NOT NULL,
    ecosystem   TEXT NOT NULL,
    reason_json TEXT,
    description TEXT,
    PRIMARY KEY (ecosystem, package_name, version, malid, blocked_at)
  );
  CREATE INDEX IF NOT EXISTS idx_malware_blocked_at ON malware(blocked_at DESC);
  CREATE INDEX IF NOT EXISTS idx_malware_package    ON malware(package_name);
  CREATE TABLE IF NOT EXISTS sync_meta (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

// Migration: add published_at column if not present
{
  const hasPubCol = db.prepare(`SELECT 1 FROM pragma_table_info('malware') WHERE name='published_at'`).get();
  if (!hasPubCol) {
    db.exec(`
      ALTER TABLE malware ADD COLUMN published_at TEXT;
      CREATE INDEX IF NOT EXISTS idx_malware_published ON malware(published_at);
    `);
  }
}

const insertMalware = db.prepare(`
  INSERT OR REPLACE INTO malware
    (package_name, version, scope, malid, source, blocked_at, ecosystem, reason_json, description)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

// ── Malware enrichment (publish-date fetch from registries) ──────────────────
const enrichState = { running: false, done: 0, total: 0, failed: 0, error: null, startedAt: null, finishedAt: null };

async function fetchNpmTimestamps(packageName) {
  const res = await fetch(`https://registry.npmjs.org/${packageName}`);
  if (!res.ok) return null;
  const data = await res.json();
  const time = data.time || {};
  const skip = new Set(['created', 'modified', 'unpublished']);
  const out = {};
  for (const [k, v] of Object.entries(time)) {
    if (!skip.has(k)) out[k] = v;
  }
  out[''] = time.created || null; // for package-wide blocks
  return out;
}

async function fetchPypiTimestamps(packageName) {
  const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`);
  if (!res.ok) return null;
  const data = await res.json();
  const releases = data.releases || {};
  const out = {};
  for (const [ver, files] of Object.entries(releases)) {
    const uploadTime = files?.[0]?.upload_time;
    if (uploadTime) out[ver] = uploadTime.endsWith('Z') ? uploadTime : uploadTime + 'Z';
  }
  const firstDate = Object.values(out).sort()[0] || null;
  out[''] = firstDate;
  return out;
}

async function fetchMavenTimestamps(packageName) {
  const slashIdx = packageName.indexOf('/');
  if (slashIdx < 0) return null;
  const group = packageName.slice(0, slashIdx);
  const artifact = packageName.slice(slashIdx + 1);
  const q = encodeURIComponent(`g:${group} AND a:${artifact}`);
  const res = await fetch(`https://search.maven.org/solrsearch/select?q=${q}&core=gav&rows=200&sort=timestamp+asc&wt=json`);
  if (!res.ok) return null;
  const data = await res.json();
  const docs = data.response?.docs || [];
  const out = {};
  for (const doc of docs) {
    if (doc.v && doc.timestamp) out[doc.v] = new Date(doc.timestamp).toISOString();
  }
  const times = Object.values(out).sort();
  out[''] = times[0] || null;
  return out;
}

async function runMalwareEnrich() {
  if (enrichState.running) throw new Error('Enrichment already in progress');
  enrichState.running = true;
  enrichState.done = 0;
  enrichState.total = 0;
  enrichState.failed = 0;
  enrichState.error = null;
  enrichState.startedAt = new Date().toISOString();
  enrichState.finishedAt = null;

  try {
    const pending = db.prepare(`
      SELECT ecosystem, package_name FROM malware
      WHERE published_at IS NULL
      GROUP BY ecosystem, package_name
      ORDER BY MAX(blocked_at) DESC
    `).all();
    enrichState.total = pending.length;

    const updateStmt = db.prepare(`UPDATE malware SET published_at = ? WHERE ecosystem = ? AND package_name = ? AND version = ?`);

    const BATCH = 20;
    for (let i = 0; i < pending.length; i += BATCH) {
      const batch = pending.slice(i, i + BATCH);
      await Promise.allSettled(batch.map(async ({ ecosystem, package_name }) => {
        try {
          let timeMap;
          if (ecosystem === 'npm')        timeMap = await fetchNpmTimestamps(package_name);
          else if (ecosystem === 'PyPI')  timeMap = await fetchPypiTimestamps(package_name);
          else                            timeMap = await fetchMavenTimestamps(package_name);

          const versions = db.prepare(
            `SELECT version FROM malware WHERE ecosystem = ? AND package_name = ? AND published_at IS NULL`
          ).all(ecosystem, package_name);

          db.transaction(() => {
            for (const { version } of versions) {
              updateStmt.run(timeMap?.[version] ?? 'NOT_FOUND', ecosystem, package_name, version);
            }
          })();
        } catch {
          db.prepare(`UPDATE malware SET published_at = 'ERROR' WHERE ecosystem = ? AND package_name = ? AND published_at IS NULL`)
            .run(ecosystem, package_name);
          enrichState.failed++;
        }
        enrichState.done++;
      }));
      await new Promise(r => setTimeout(r, 0));
    }
  } catch (err) {
    enrichState.error = err.message;
    throw err;
  } finally {
    enrichState.running = false;
    enrichState.finishedAt = new Date().toISOString();
  }
}

// ── Platform API token (server-side storage + auto-refresh) ───────────────────

// Platform API ecosystem values and their DB names
const PLATFORM_ECOSYSTEMS = [
  { apiName: 'npm',   dbName: 'npm'   },
  { apiName: 'Maven', dbName: 'Maven' },
  { apiName: 'PyPI',  dbName: 'PyPI'  },
];

let platformToken = process.env.PLATFORM_API_TOKEN || null;
let platformTokenExpiry = null; // Unix timestamp (ms)
let tokenRefreshTimer = null;

function parsePlatformTokenExpiry(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
    return payload.exp ? payload.exp * 1000 : null;
  } catch { return null; }
}

function setPlatformToken(token) {
  platformToken = token || null;
  platformTokenExpiry = token ? parsePlatformTokenExpiry(token) : null;
  if (tokenRefreshTimer) { clearTimeout(tokenRefreshTimer); tokenRefreshTimer = null; }
  if (platformTokenExpiry) scheduleTokenRefresh();
}

async function refreshPlatformTokenViaChainctl() {
  try {
    const proc = Bun.spawn(['chainctl', 'auth', 'token', '--audience', 'https://console-api.enforce.dev'], {
      stdout: 'pipe', stderr: 'pipe',
    });
    const text = await new Response(proc.stdout).text();
    const code = await proc.exited;
    if (code !== 0) throw new Error(`chainctl exited ${code}`);
    const token = text.trim();
    if (!token) throw new Error('empty token');
    setPlatformToken(token);
    console.log('Platform token refreshed via chainctl, expires', new Date(platformTokenExpiry).toISOString());
    return token;
  } catch (err) {
    console.error('chainctl token refresh failed:', err.message);
    return null;
  }
}

function scheduleTokenRefresh() {
  if (!platformTokenExpiry) return;
  const refreshAt = platformTokenExpiry - 5 * 60 * 1000; // 5 min before expiry
  const delay = Math.max(0, refreshAt - Date.now());
  tokenRefreshTimer = setTimeout(async () => {
    await refreshPlatformTokenViaChainctl();
  }, delay);
}

// Seed from env var on startup
if (platformToken) {
  platformTokenExpiry = parsePlatformTokenExpiry(platformToken);
  if (platformTokenExpiry) scheduleTokenRefresh();
}

// ── Malware sync ──────────────────────────────────────────────────────────────

const syncState = { running: false, fetched: 0, total: 0, error: null, startedAt: null, finishedAt: null };

function malwareStatus() {
  const counts = db.prepare(`SELECT ecosystem, COUNT(*) AS n, MAX(blocked_at) AS latest FROM malware GROUP BY ecosystem`).all();
  const byEco = Object.fromEntries(counts.map(r => [r.ecosystem, { total: r.n, latest: r.latest }]));
  const total = counts.reduce((s, r) => s + r.n, 0);
  const lastSync = db.prepare(`SELECT value FROM sync_meta WHERE key = 'last_sync_at'`).get();
  const tokenStatus = platformToken
    ? { set: true, expiresAt: platformTokenExpiry ? new Date(platformTokenExpiry).toISOString() : null }
    : { set: false };
  const enrichCounts = db.prepare(`
    SELECT
      COUNT(*) AS total,
      COUNT(CASE WHEN published_at IS NOT NULL AND published_at NOT IN ('NOT_FOUND','ERROR') THEN 1 END) AS enriched,
      COUNT(CASE WHEN published_at IS NULL THEN 1 END) AS pending,
      COUNT(CASE WHEN published_at IN ('NOT_FOUND','ERROR') THEN 1 END) AS unavailable
    FROM malware
  `).get();
  return { total, byEco, lastSyncAt: lastSync?.value || null, sync: { ...syncState }, platformToken: tokenStatus, enrich: { ...enrichCounts, state: { ...enrichState } } };
}

const SCOPE_NORM = { 'MALWARE_SCOPE_VERSION': 'version', 'MALWARE_SCOPE_PACKAGE': 'package', 'MALWARE_SCOPE_UNKNOWN': '' };
function normScope(s) { return SCOPE_NORM[s] ?? s ?? ''; }

function insertItems(items, ecoName) {
  const tx = db.transaction(rows => {
    for (const it of rows) {
      insertMalware.run(
        it.package_name ?? it.packageName,
        it.version ?? '',
        normScope(it.scope),
        it.malid ?? '',
        it.source ?? null,
        it.blocked_at ?? it.blockedAt,
        it.ecosystem || ecoName,
        JSON.stringify(it.reason || []),
        it.description ?? null,
      );
    }
  });
  tx(items);
  syncState.fetched += items.length;
}

async function runMalwareSync({ token, full = false }) {
  if (syncState.running) throw new Error('Sync already in progress');
  if (!token) throw new Error('No platform token available');
  syncState.running = true;
  syncState.fetched = 0;
  syncState.total = 0;
  syncState.error = null;
  syncState.startedAt = new Date().toISOString();
  syncState.finishedAt = null;
  const apiBase = 'https://console-api.enforce.dev/libraries/v1/malware/blocklist';
  try {
    for (const { apiName, dbName } of PLATFORM_ECOSYSTEMS) {
      let savedPubDates = null;
      if (full) {
        savedPubDates = db.prepare(
          `SELECT package_name, version, published_at FROM malware WHERE ecosystem = ? AND published_at IS NOT NULL`
        ).all(dbName);
        db.prepare(`DELETE FROM malware WHERE ecosystem = ?`).run(dbName);
      }
      let since = '2026-01-01T00:00:00Z';
      if (!full) {
        const latest = db.prepare(`SELECT MAX(blocked_at) AS m FROM malware WHERE ecosystem = ?`).get(dbName);
        if (latest?.m) since = latest.m;
      }
      let pageToken = null;
      while (true) {
        const params = new URLSearchParams({ ecosystem: apiName, pageSize: '500' });
        if (since) params.set('since', since);
        if (pageToken) params.set('pageToken', pageToken);
        const res = await fetch(`${apiBase}?${params}`, { headers: { Authorization: `Bearer ${token}` } });
        if (!res.ok) throw new Error(`HTTP ${res.status} from Platform API (${apiName})`);
        const data = await res.json();
        const items = data.items || [];
        insertItems(items, dbName);
        if (!data.nextPageToken || items.length === 0) break;
        pageToken = data.nextPageToken;
      }
      if (full && savedPubDates?.length) {
        const restoreStmt = db.prepare(
          `UPDATE malware SET published_at = ? WHERE ecosystem = ? AND package_name = ? AND version = ?`
        );
        db.transaction(() => {
          for (const row of savedPubDates) restoreStmt.run(row.published_at, dbName, row.package_name, row.version);
        })();
      }
    }
    db.prepare(`INSERT OR REPLACE INTO sync_meta (key, value) VALUES ('last_sync_at', ?)`).run(new Date().toISOString());
  } catch (err) {
    syncState.error = err.message;
    throw err;
  } finally {
    syncState.running = false;
    syncState.finishedAt = new Date().toISOString();
  }
}

Bun.serve({
  port: 3000,
  idleTimeout: 60,
  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === '/') {
      return new Response(Bun.file(htmlPath), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // npm / JS proxy
    if (url.pathname.startsWith('/api/cgr/')) {
      const pkg = url.pathname.slice('/api/cgr/'.length);
      const user = req.headers.get('x-cgr-user') || '';
      const pass = req.headers.get('x-cgr-pass') || '';
      const upstream = `https://libraries.cgr.dev/javascript/${pkg}`;
      const headers = user ? { 'Authorization': 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64') } : {};
      try {
        const res = await fetch(upstream, { headers });
        const body = await res.text();
        return new Response(body, { status: res.status, headers: { 'Content-Type': 'application/json' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // CGR authenticated download proxy (streams tarball back as attachment)
    if (url.pathname.startsWith('/api/cgr-download/')) {
      const path = url.pathname.slice('/api/cgr-download/'.length);
      const user = req.headers.get('x-cgr-user') || '';
      const pass = req.headers.get('x-cgr-pass') || '';
      const upstream = `https://libraries.cgr.dev/${path}`;
      const headers = user ? { 'Authorization': 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64') } : {};
      try {
        const res = await fetch(upstream, { headers });
        const filename = path.split('/').pop() || 'download';
        const respHeaders = {
          'Content-Type': res.headers.get('content-type') || 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${filename}"`,
        };
        const len = res.headers.get('content-length');
        if (len) respHeaders['Content-Length'] = len;
        return new Response(res.body, { status: res.status, headers: respHeaders });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // CGR npm attestations proxy
    if (url.pathname.startsWith('/api/cgr-attestations/')) {
      const path = url.pathname.slice('/api/cgr-attestations/'.length);
      const user = req.headers.get('x-cgr-user') || '';
      const pass = req.headers.get('x-cgr-pass') || '';
      const upstream = `https://libraries.cgr.dev/javascript/-/npm/v1/attestations/${path}`;
      const headers = user ? { 'Authorization': 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64') } : {};
      try {
        const res = await fetch(upstream, { headers });
        const body = await res.text();
        return new Response(body, { status: res.status, headers: { 'Content-Type': 'application/json' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // npm attestation verification (fetch + cryptographic verify via sigstore)
    if (url.pathname === '/api/verify-attestation') {
      const pkg = url.searchParams.get('pkg');
      const version = url.searchParams.get('version');
      if (!pkg || !version) return new Response('Missing pkg or version', { status: 400 });
      const user = req.headers.get('x-cgr-user') || '';
      const pass = req.headers.get('x-cgr-pass') || '';
      const cgrAuthHeaders = user ? { 'Authorization': 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64') } : {};
      const pkgVer = `${pkg}@${version}`;

      function extractCommitFromPayload(payload, predicateType) {
        let commit = null, uri = null;
        if (predicateType === 'https://slsa.dev/provenance/v1') {
          const deps = payload.predicate?.buildDefinition?.resolvedDependencies ?? [];
          for (const dep of deps) {
            if (dep?.digest?.gitCommit && dep?.uri) { commit = dep.digest.gitCommit; uri = dep.uri; break; }
          }
        } else if (predicateType === 'https://slsa.dev/provenance/v0.2') {
          const src = payload.predicate?.invocation?.configSource ?? payload.predicate?.materials?.[0];
          commit = src?.digest?.sha1 ?? src?.digest?.gitCommit ?? null;
          uri = src?.uri ?? null;
        }
        if (!commit || !uri) return { commitUrl: null, shortSha: null };
        let repoUrl = null;
        const purlMatch = uri.match(/^pkg:github\/([^@]+)/);
        if (purlMatch) {
          repoUrl = `https://github.com/${purlMatch[1]}`;
        } else {
          const candidate = uri.replace(/^git\+/, '').replace(/@.*$/, '');
          if (/^https:\/\/(github|gitlab|bitbucket)\.com\//.test(candidate)) repoUrl = candidate;
        }
        return repoUrl
          ? { commitUrl: `${repoUrl}/commit/${commit}`, shortSha: commit.slice(0, 7) }
          : { commitUrl: null, shortSha: null };
      }

      async function processAttestations(data) {
        if (!data?.attestations?.length) return { hasAttestation: false };
        const SLSA_TYPES = new Set(['https://slsa.dev/provenance/v1', 'https://slsa.dev/provenance/v0.2']);
        for (const att of data.attestations) {
          if (!SLSA_TYPES.has(att.predicateType)) continue;

          let commitUrl = null, shortSha = null;
          try {
            const payload = JSON.parse(Buffer.from(att.bundle.dsseEnvelope.payload, 'base64').toString());
            ({ commitUrl, shortSha } = extractCommitFromPayload(payload, att.predicateType));
          } catch {}

          let verified = false, identity = null, tlogIndex = null;
          try {
            const certBytes = att.bundle.verificationMaterial?.certificate?.rawBytes
              ?? att.bundle.verificationMaterial?.x509CertificateChain?.certificates?.[0]?.rawBytes;
            if (certBytes) {
              const certDer = Buffer.from(certBytes, 'base64');
              const pemCert = '-----BEGIN CERTIFICATE-----\n' + certDer.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n';
              const pubKey = createPublicKey({ key: pemCert, format: 'pem' });
              const x509 = new X509Certificate(certDer);
              const dsse = att.bundle.dsseEnvelope;
              const payloadBuf = Buffer.from(dsse.payload, 'base64');
              const pae = Buffer.concat([
                Buffer.from(`DSSEv1 ${dsse.payloadType.length} ${dsse.payloadType} ${payloadBuf.length} `),
                payloadBuf,
              ]);
              const sigBuf = Buffer.from(dsse.signatures[0].sig, 'base64');
              if (cryptoVerify('SHA256', pae, pubKey, sigBuf) && x509.issuer?.includes('sigstore')) {
                verified = true;
                const san = x509.subjectAltName || '';
                const uriMatch = san.match(/URI:([^\s,]+)/);
                identity = uriMatch ? uriMatch[1] : null;
                tlogIndex = att.bundle.verificationMaterial?.tlogEntries?.[0]?.logIndex ?? null;
              }
            }
          } catch {}

          return { hasAttestation: true, verified, commitUrl, shortSha, identity, tlogIndex };
        }
        // No SLSA attestation found — only show badge if non-npm-publish types exist
        const NPM_PUBLISH = 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1';
        return data.attestations.some(att => att.predicateType !== NPM_PUBLISH)
          ? { hasAttestation: true, verified: false, commitUrl: null, shortSha: null, identity: null }
          : { hasAttestation: false };
      }

      try {
        const [npmRes, cgrRes] = await Promise.allSettled([
          fetch(`https://registry.npmjs.org/-/npm/v1/attestations/${pkgVer}`).then(r => r.ok ? r.json() : null).catch(() => null),
          fetch(`https://libraries.cgr.dev/javascript/-/npm/v1/attestations/${pkgVer}`, { headers: cgrAuthHeaders }).then(r => r.ok ? r.json() : null).catch(() => null),
        ]);
        const [npmResult, cgrResult] = await Promise.all([
          processAttestations(npmRes.status === 'fulfilled' ? npmRes.value : null),
          processAttestations(cgrRes.status === 'fulfilled' ? cgrRes.value : null),
        ]);
        return new Response(JSON.stringify({ npm: npmResult, cgr: cgrResult }), { headers: { 'Content-Type': 'application/json' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // Maven metadata
    if (url.pathname === '/api/maven-metadata') {
      const group = url.searchParams.get('group');
      const artifact = url.searchParams.get('artifact');
      if (!group || !artifact) return new Response('Missing group or artifact', { status: 400 });
      const groupPath = group.replace(/\./g, '/');
      const upstream = `https://repo1.maven.org/maven2/${groupPath}/${artifact}/maven-metadata.xml`;
      try {
        const res = await fetch(upstream, { headers: { 'User-Agent': 'maven-browser/1.0', 'Accept': 'application/xml, */*' } });
        const body = await res.text();
        return new Response(body, { status: res.status, headers: { 'Content-Type': 'application/xml' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // Maven timestamps (search.maven.org Solr)
    if (url.pathname === '/api/maven-timestamps') {
      const group = url.searchParams.get('group');
      const artifact = url.searchParams.get('artifact');
      const start = parseInt(url.searchParams.get('start') || '0', 10);
      if (!group || !artifact) return new Response('Missing group or artifact', { status: 400 });
      const q = encodeURIComponent(`g:${group} AND a:${artifact}`);
      const upstream = `https://search.maven.org/solrsearch/select?q=${q}&core=gav&rows=200&start=${start}&sort=timestamp+desc&wt=json`;
      try {
        const res = await fetch(upstream);
        const body = await res.text();
        return new Response(body, { status: res.status, headers: { 'Content-Type': 'application/json' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // Maven fallback dates via HEAD on POM files
    if (url.pathname === '/api/maven-dates' && req.method === 'POST') {
      const { group, artifact, versions } = await req.json();
      if (!group || !artifact || !Array.isArray(versions)) return new Response('Bad request', { status: 400 });
      const groupPath = group.replace(/\./g, '/');
      const results = await Promise.all(
        versions.map(async v => {
          const pomUrl = `https://repo1.maven.org/maven2/${groupPath}/${artifact}/${v}/${artifact}-${v}.pom`;
          try {
            const res = await fetch(pomUrl, { method: 'HEAD', headers: { 'User-Agent': 'maven-browser/1.0' } });
            const lastModified = res.headers.get('last-modified');
            return [v, lastModified ? new Date(lastModified).getTime() : null];
          } catch {
            return [v, null];
          }
        })
      );
      return new Response(JSON.stringify(Object.fromEntries(results)), { headers: { 'Content-Type': 'application/json' } });
    }

    // Maven / Java CGR proxy
    if (url.pathname === '/api/cgr-java') {
      const group = url.searchParams.get('group');
      const artifact = url.searchParams.get('artifact');
      const repo = url.searchParams.get('repo') || 'java';
      const user = req.headers.get('x-cgr-user') || '';
      const pass = req.headers.get('x-cgr-pass') || '';
      if (!group || !artifact) return new Response('Missing group or artifact', { status: 400 });
      const groupPath = group.replace(/\./g, '/');
      const upstream = `https://libraries.cgr.dev/${repo}/${groupPath}/${artifact}/maven-metadata.xml`;
      const headers = user ? { 'Authorization': 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64') } : {};
      try {
        const res = await fetch(upstream, { headers });
        const body = await res.text();
        return new Response(body, { status: res.status, headers: { 'Content-Type': 'application/xml' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // PyPI / Python CGR proxy — PEP 503 simple index
    if (url.pathname.startsWith('/api/cgr-python/')) {
      const path = url.pathname.slice('/api/cgr-python/'.length);
      const user = req.headers.get('x-cgr-user') || '';
      const pass = req.headers.get('x-cgr-pass') || '';
      const upstream = `https://libraries.cgr.dev/python/${path}`;
      const headers = user ? { 'Authorization': 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64') } : {};
      try {
        const res = await fetch(upstream, { headers });
        const body = await res.text();
        const ct = res.headers.get('content-type') || 'text/html';
        return new Response(body, { status: res.status, headers: { 'Content-Type': ct } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // Malware cache status
    if (url.pathname === '/api/cgr-malware/status') {
      return new Response(JSON.stringify(malwareStatus()), { headers: { 'Content-Type': 'application/json' } });
    }

    // Platform token management
    if (url.pathname === '/api/platform-token' && req.method === 'POST') {
      const body = await req.json().catch(() => ({}));
      const token = (body.token || '').trim();
      setPlatformToken(token || null);
      return new Response(JSON.stringify({ ok: true, status: malwareStatus().platformToken }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (url.pathname === '/api/platform-token/refresh' && req.method === 'POST') {
      const token = await refreshPlatformTokenViaChainctl();
      if (!token) return new Response(JSON.stringify({ error: 'chainctl refresh failed — check server logs' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
      return new Response(JSON.stringify({ ok: true, status: malwareStatus().platformToken }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Malware cache sync (fire-and-forget). Server kicks off the sync in the
    // background; client polls /api/cgr-malware/status for progress.
    if (url.pathname === '/api/cgr-malware/sync' && req.method === 'POST') {
      if (syncState.running) {
        return new Response(JSON.stringify({ error: 'Sync already in progress', status: malwareStatus() }), { status: 409, headers: { 'Content-Type': 'application/json' } });
      }
      const body = await req.json().catch(() => ({}));
      const full = body.full === true;
      // Client can supply a token to override the server-stored one (e.g. fresh paste from settings)
      const token = (body.platformToken || '').trim() || platformToken;
      if (body.platformToken?.trim()) setPlatformToken(body.platformToken.trim());
      if (!token) return new Response(JSON.stringify({ error: 'No platform token set — paste one in Settings first' }), { status: 401, headers: { 'Content-Type': 'application/json' } });

      runMalwareSync({ token, full }).catch(() => { /* err captured in syncState.error */ });

      return new Response(JSON.stringify({ started: true, status: malwareStatus() }), { status: 202, headers: { 'Content-Type': 'application/json' } });
    }

    // Malware enrichment (fire-and-forget).
    if (url.pathname === '/api/cgr-malware/enrich' && req.method === 'POST') {
      if (enrichState.running) {
        return new Response(JSON.stringify({ error: 'Enrichment already in progress', state: enrichState }), { status: 409, headers: { 'Content-Type': 'application/json' } });
      }
      runMalwareEnrich().catch(() => {});
      return new Response(JSON.stringify({ started: true, state: enrichState }), { status: 202, headers: { 'Content-Type': 'application/json' } });
    }

    // Enrichment status.
    if (url.pathname === '/api/cgr-malware/enrich/status') {
      const counts = db.prepare(`
        SELECT
          COUNT(*) AS total,
          COUNT(CASE WHEN published_at IS NOT NULL AND published_at NOT IN ('NOT_FOUND','ERROR') THEN 1 END) AS enriched,
          COUNT(CASE WHEN published_at IS NULL THEN 1 END) AS pending,
          COUNT(CASE WHEN published_at IN ('NOT_FOUND','ERROR') THEN 1 END) AS unavailable
        FROM malware
      `).get();
      return new Response(JSON.stringify({ ...counts, enrichState: { ...enrichState } }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Detection lag statistics.
    if (url.pathname === '/api/cgr-malware/stats') {
      const eco   = url.searchParams.get('eco')   || '';
      const since = url.searchParams.get('since') || '';
      const until = url.searchParams.get('until') || '';

      const pub_since = url.searchParams.get('pub_since') || '';
      const pub_until = url.searchParams.get('pub_until') || '';

      const where = [`published_at IS NOT NULL`, `published_at NOT IN ('NOT_FOUND','ERROR')`, `blocked_at >= published_at`];
      const args = [];
      if (eco)       { where.push('ecosystem = ?');    args.push(eco); }
      if (since)     { where.push('blocked_at >= ?');  args.push(since); }
      if (until)     { where.push('blocked_at <  ?');  args.push(until); }
      if (pub_since) { where.push('published_at >= ?'); args.push(pub_since); }
      if (pub_until) { where.push('published_at <  ?'); args.push(pub_until); }
      const whereSql = `WHERE ${where.join(' AND ')}`;
      const lagExpr = `(julianday(blocked_at) - julianday(published_at)) * 86400.0`;

      const overall = db.prepare(
        `SELECT COUNT(*) AS n, AVG(${lagExpr}) AS mean_s, MIN(${lagExpr}) AS min_s, MAX(${lagExpr}) AS max_s FROM malware ${whereSql}`
      ).get(...args);

      const medianRow = overall.n > 0 ? db.prepare(`
        WITH ranked AS (
          SELECT ${lagExpr} AS lag_s, ROW_NUMBER() OVER (ORDER BY ${lagExpr}) AS rn, COUNT(*) OVER () AS total
          FROM malware ${whereSql}
        )
        SELECT AVG(lag_s) AS median_s FROM ranked WHERE rn IN ((total+1)/2, (total+2)/2)
      `).get(...args) : null;

      const p90Row = overall.n > 0 ? db.prepare(`
        WITH ranked AS (
          SELECT ${lagExpr} AS lag_s, ROW_NUMBER() OVER (ORDER BY ${lagExpr}) AS rn, COUNT(*) OVER () AS total
          FROM malware ${whereSql}
        )
        SELECT lag_s AS p90_s FROM ranked WHERE rn = CAST(CEIL(total * 0.9) AS INTEGER) LIMIT 1
      `).get(...args) : null;

      const byEco = db.prepare(
        `SELECT ecosystem, COUNT(*) AS n, AVG(${lagExpr}) AS mean_s, MIN(${lagExpr}) AS min_s, MAX(${lagExpr}) AS max_s FROM malware ${whereSql} GROUP BY ecosystem`
      ).all(...args);

      const histogram = db.prepare(`
        SELECT
          CASE
            WHEN ${lagExpr} < 3600    THEN '<1h'
            WHEN ${lagExpr} < 21600   THEN '1-6h'
            WHEN ${lagExpr} < 86400   THEN '6-24h'
            WHEN ${lagExpr} < 604800  THEN '1-7d'
            WHEN ${lagExpr} < 2592000 THEN '7-30d'
            WHEN ${lagExpr} < 7776000 THEN '30-90d'
            ELSE '>90d'
          END AS bucket,
          COUNT(*) AS n
        FROM malware ${whereSql}
        GROUP BY bucket
      `).all(...args);

      const BUCKET_ORDER = ['<1h','1-6h','6-24h','1-7d','7-30d','30-90d','>90d'];
      histogram.sort((a, b) => BUCKET_ORDER.indexOf(a.bucket) - BUCKET_ORDER.indexOf(b.bucket));

      return new Response(JSON.stringify({
        overall: { ...overall, median_s: medianRow?.median_s ?? null, p90_s: p90Row?.p90_s ?? null },
        byEco,
        histogram,
      }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Malware search (filtered, server-side).
    if (url.pathname === '/api/cgr-malware/search') {
      const eco     = url.searchParams.get('eco')     || '';
      const q       = url.searchParams.get('q')       || '';
      const ver     = url.searchParams.get('version') || '';
      const reason  = url.searchParams.get('reason')  || '';
      const src     = url.searchParams.get('source')  || '';
      const since   = url.searchParams.get('since')   || '';
      const until   = url.searchParams.get('until')   || '';
      const exact   = url.searchParams.get('exact')   === '1';
      const limit   = Math.min(parseInt(url.searchParams.get('limit')  || '200', 10) || 200, 1000);
      const offset  = parseInt(url.searchParams.get('offset') || '0',  10) || 0;

      const where = eco ? ['ecosystem = ?'] : [];
      const args  = eco ? [eco] : [];
      if (q)     { where.push(exact ? 'package_name = ?' : 'package_name LIKE ?'); args.push(exact ? q : `%${q}%`); }
      if (ver)   { where.push(exact ? 'version = ?'      : 'version LIKE ?');      args.push(exact ? ver : `%${ver}%`); }
      if (reason){ where.push('reason_json LIKE ?');  args.push(`%${reason}%`); }
      if (src)   { where.push('source = ?');          args.push(src); }
      if (since) { where.push('blocked_at >= ?');     args.push(since); }
      if (until) { where.push('blocked_at <  ?');     args.push(until); }
      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

      const total = db.prepare(`SELECT COUNT(*) AS n FROM malware ${whereSql}`).get(...args).n;
      const rows  = db.prepare(`
        SELECT package_name, version, scope, malid, source, blocked_at, ecosystem, reason_json, description, published_at
        FROM malware ${whereSql}
        ORDER BY blocked_at DESC
        LIMIT ? OFFSET ?
      `).all(...args, limit, offset);
      const SENTINELS = new Set(['NOT_FOUND', 'ERROR']);
      const out = rows.map(r => ({
        ...r,
        reason: JSON.parse(r.reason_json || '[]'),
        reason_json: undefined,
        published_at: (r.published_at && !SENTINELS.has(r.published_at)) ? r.published_at : null,
      }));
      return new Response(JSON.stringify({ total, rows: out, limit, offset }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Per-day findings histogram (same filter shape as /search).
    if (url.pathname === '/api/cgr-malware/histogram') {
      const eco    = url.searchParams.get('eco')     || '';
      const q      = url.searchParams.get('q')       || '';
      const ver    = url.searchParams.get('version') || '';
      const reason = url.searchParams.get('reason')  || '';
      const src    = url.searchParams.get('source')  || '';
      const since  = url.searchParams.get('since')   || '';
      const until  = url.searchParams.get('until')   || '';
      const exact  = url.searchParams.get('exact')   === '1';
      const where = eco ? ['ecosystem = ?'] : [];
      const args  = eco ? [eco] : [];
      if (q)     { where.push(exact ? 'package_name = ?' : 'package_name LIKE ?'); args.push(exact ? q : `%${q}%`); }
      if (ver)   { where.push(exact ? 'version = ?'      : 'version LIKE ?');      args.push(exact ? ver : `%${ver}%`); }
      if (reason){ where.push('reason_json LIKE ?');  args.push(`%${reason}%`); }
      if (src)   { where.push('source = ?');          args.push(src); }
      if (since) { where.push('blocked_at >= ?');     args.push(since); }
      if (until) { where.push('blocked_at <  ?');     args.push(until); }
      const whereSql = `WHERE ${where.join(' AND ')}`;
      const rows = db.prepare(`
        SELECT substr(blocked_at, 1, 10) AS day, COUNT(*) AS n
        FROM malware ${whereSql}
        GROUP BY day
        ORDER BY day
      `).all(...args);
      return new Response(JSON.stringify(rows), { headers: { 'Content-Type': 'application/json' } });
    }

    // All malware entries for one package (any version, any source).
    // Used by the npm tab to badge versions/packages flagged as malware.
    if (url.pathname === '/api/cgr-malware/check') {
      const pkg = url.searchParams.get('package') || '';
      const ecoParam = url.searchParams.get('eco') || 'npm';
      const ecoDbName = ecoParam === 'maven' ? 'Maven' : ecoParam === 'pypi' ? 'PyPI' : 'npm';
      if (!pkg) return new Response(JSON.stringify({ rows: [] }), { headers: { 'Content-Type': 'application/json' } });
      const rows = db.prepare(`
        SELECT package_name, version, scope, malid, source, blocked_at, reason_json, description
        FROM malware
        WHERE ecosystem = ? AND package_name = ?
      `).all(ecoDbName, pkg);
      const out = rows.map(r => ({ ...r, reason: JSON.parse(r.reason_json || '[]'), reason_json: undefined }));
      return new Response(JSON.stringify({ rows: out }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Distinct reasons (for filter facets). Individual MAL-YYYY-N advisory IDs
    // are collapsed into a single "MAL-ID*" bucket; the row carries a
    // `searchAs` field so the client can submit a prefix to the search endpoint.
    if (url.pathname === '/api/cgr-malware/reasons') {
      const eco = url.searchParams.get('eco') || '';
      const ecoFilter = eco ? `AND m.ecosystem = ?` : '';
      const rows = db.prepare(`
        SELECT
          CASE WHEN je.value GLOB 'MAL-[0-9]*-[0-9]*' THEN 'MAL-ID*' ELSE je.value END AS reason,
          COUNT(DISTINCT m.rowid) AS n
        FROM malware m, json_each(m.reason_json) je
        WHERE 1=1 ${ecoFilter}
        GROUP BY reason
        ORDER BY reason COLLATE NOCASE
      `).all(...(eco ? [eco] : []));
      for (const r of rows) {
        if (r.reason === 'MAL-ID*') r.searchAs = 'MAL-';
      }
      return new Response(JSON.stringify(rows), { headers: { 'Content-Type': 'application/json' } });
    }

    return new Response('Not found', { status: 404 });
  },
});

console.log('Listening on http://localhost:3000');
process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
