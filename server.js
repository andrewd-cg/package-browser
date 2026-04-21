// Run with: ~/.bun/bin/bun server.js
const htmlPath = new URL('./index.html', import.meta.url);

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

    return new Response('Not found', { status: 404 });
  },
});

console.log('Listening on http://localhost:3000');
process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
