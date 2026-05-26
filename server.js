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

const insertMalware = db.prepare(`
  INSERT OR REPLACE INTO malware
    (package_name, version, scope, malid, source, blocked_at, ecosystem, reason_json, description)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const syncState = { running: false, fetched: 0, total: 0, error: null, startedAt: null, finishedAt: null };

function malwareStatus() {
  const row = db.prepare(`SELECT COUNT(*) AS total, MAX(blocked_at) AS latest FROM malware WHERE ecosystem = 'npm'`).get();
  const lastSync = db.prepare(`SELECT value FROM sync_meta WHERE key = 'last_sync_at'`).get();
  return {
    total: row.total,
    latest: row.latest,
    lastSyncAt: lastSync?.value || null,
    sync: { ...syncState },
  };
}

async function runMalwareSync({ user, pass, since, ecosystem = 'javascript' }) {
  if (syncState.running) throw new Error('Sync already in progress');
  syncState.running = true;
  syncState.fetched = 0;
  syncState.total = 0;
  syncState.error = null;
  syncState.startedAt = new Date().toISOString();
  syncState.finishedAt = null;

  const auth = 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
  // Map UI ecosystem name to API path segment (only javascript is exposed today).
  const apiBase = `https://libraries.cgr.dev/${ecosystem}/-/api/malware`;
  const ecoName = ecosystem === 'javascript' ? 'npm' : ecosystem;

  try {
    let pageToken = null;
    let yielded = 0;
    while (true) {
      const params = new URLSearchParams();
      if (since) params.set('since', since);
      if (pageToken) params.set('page_token', pageToken);
      params.set('page_size', '500');
      const res = await fetch(`${apiBase}?${params}`, { headers: { Authorization: auth } });
      if (!res.ok) throw new Error(`HTTP ${res.status} from malware API`);
      const data = await res.json();
      if (typeof data.total_count === 'number') syncState.total = data.total_count;
      const items = data.items || [];
      const tx = db.transaction(rows => {
        for (const it of rows) {
          insertMalware.run(
            it.package_name,
            it.version ?? null,
            it.scope ?? null,
            it.malid ?? null,
            it.source ?? null,
            it.blocked_at,
            it.ecosystem || ecoName,
            JSON.stringify(it.reason || []),
            it.description ?? null,
          );
        }
      });
      tx(items);
      yielded += items.length;
      syncState.fetched = yielded;
      if (!data.next_page_token || items.length === 0) break;
      pageToken = data.next_page_token;
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

    // Malware cache sync (incremental). Streams NDJSON progress lines while running.
    if (url.pathname === '/api/cgr-malware/sync' && req.method === 'POST') {
      if (syncState.running) {
        return new Response(JSON.stringify({ error: 'Sync already in progress', status: malwareStatus() }), { status: 409, headers: { 'Content-Type': 'application/json' } });
      }
      const user = req.headers.get('x-cgr-user') || '';
      const pass = req.headers.get('x-cgr-pass') || '';
      if (!user) return new Response(JSON.stringify({ error: 'Missing credentials' }), { status: 401, headers: { 'Content-Type': 'application/json' } });

      const body = await req.json().catch(() => ({}));
      const fullSync = body.full === true;
      let since = body.since || '2026-01-01T00:00:00Z';
      if (!fullSync) {
        const latest = db.prepare(`SELECT MAX(blocked_at) AS m FROM malware WHERE ecosystem = 'npm'`).get();
        if (latest?.m) since = latest.m;
      }

      const stream = new ReadableStream({
        async start(ctrl) {
          const enc = new TextEncoder();
          const emit = obj => ctrl.enqueue(enc.encode(JSON.stringify(obj) + '\n'));
          const ticker = setInterval(() => emit({ progress: { fetched: syncState.fetched, total: syncState.total } }), 400);
          try {
            emit({ start: { since } });
            await runMalwareSync({ user, pass, since });
            emit({ done: malwareStatus() });
          } catch (err) {
            emit({ error: err.message });
          } finally {
            clearInterval(ticker);
            ctrl.close();
          }
        },
      });
      return new Response(stream, { headers: { 'Content-Type': 'application/x-ndjson' } });
    }

    // Malware search (filtered, server-side).
    if (url.pathname === '/api/cgr-malware/search') {
      const q       = url.searchParams.get('q')       || '';
      const ver     = url.searchParams.get('version') || '';
      const reason  = url.searchParams.get('reason')  || '';
      const since   = url.searchParams.get('since')   || '';
      const until   = url.searchParams.get('until')   || '';
      const limit   = Math.min(parseInt(url.searchParams.get('limit')  || '200', 10) || 200, 1000);
      const offset  = parseInt(url.searchParams.get('offset') || '0',  10) || 0;

      const where = ["ecosystem = 'npm'"];
      const args  = [];
      if (q)     { where.push('package_name LIKE ?'); args.push(`%${q}%`); }
      if (ver)   { where.push('version LIKE ?');      args.push(`%${ver}%`); }
      if (reason){ where.push('reason_json LIKE ?');  args.push(`%${reason}%`); }
      if (since) { where.push('blocked_at >= ?');     args.push(since); }
      if (until) { where.push('blocked_at <  ?');     args.push(until); }
      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

      const total = db.prepare(`SELECT COUNT(*) AS n FROM malware ${whereSql}`).get(...args).n;
      const rows  = db.prepare(`
        SELECT package_name, version, scope, malid, source, blocked_at, ecosystem, reason_json, description
        FROM malware ${whereSql}
        ORDER BY blocked_at DESC
        LIMIT ? OFFSET ?
      `).all(...args, limit, offset);
      const out = rows.map(r => ({ ...r, reason: JSON.parse(r.reason_json || '[]'), reason_json: undefined }));
      return new Response(JSON.stringify({ total, rows: out, limit, offset }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Distinct reasons (for filter facets). Individual MAL-YYYY-N advisory IDs
    // are collapsed into a single "MAL-ID*" bucket; the row carries a
    // `searchAs` field so the client can submit a prefix to the search endpoint.
    if (url.pathname === '/api/cgr-malware/reasons') {
      const rows = db.prepare(`
        SELECT
          CASE WHEN je.value GLOB 'MAL-[0-9]*-[0-9]*' THEN 'MAL-ID*' ELSE je.value END AS reason,
          COUNT(DISTINCT m.rowid) AS n
        FROM malware m, json_each(m.reason_json) je
        WHERE m.ecosystem = 'npm'
        GROUP BY reason
        ORDER BY reason COLLATE NOCASE
      `).all();
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
