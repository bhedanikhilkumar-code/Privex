// scripts/verify-live-production-pages.js
import https from 'https';

function fetchUrl(urlPath) {
  return new Promise((resolve, reject) => {
    https.get('https://privex.pages.dev' + urlPath, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: data,
        size: Buffer.byteLength(data)
      }));
    }).on('error', reject);
  });
}

async function verifyLive() {
  console.log('--- Verifying Live Cloudflare Production Deployment ---');
  const root = await fetchUrl('/');
  console.log('Root HTML Status:', root.status, 'Size:', root.size);

  const scriptMatches = root.body.match(/\/assets\/[^"']+\.js/g) || [];
  const cssMatches = root.body.match(/\/assets\/[^"']+\.css/g) || [];
  console.log('Discovered Script Chunks:', scriptMatches);
  console.log('Discovered CSS Chunks:', cssMatches);

  for (const s of [...scriptMatches, ...cssMatches]) {
    const asset = await fetchUrl(s);
    console.log(s, 'Status:', asset.status, 'Content-Type:', asset.headers['content-type'], 'Size:', asset.size);
    if (asset.status !== 200) {
      throw new Error(`Failed to fetch ${s}: ${asset.status}`);
    }
  }

  // Verify deep routing rewrite
  const deepRoute = await fetchUrl('/scanner');
  console.log('Deep Route /scanner Status:', deepRoute.status, 'Matches Index HTML:', deepRoute.body.includes('id="root"'));
  if (deepRoute.status !== 200 || !deepRoute.body.includes('id="root"')) {
    throw new Error('Deep routing /scanner failed SPA rewrite');
  }

  console.log('--- ALL STATIC PRODUCTION ASSETS VERIFIED ON CLOUDFLARE EDGE ---');
}

verifyLive().catch(err => {
  console.error('Verification failed:', err);
  process.exit(1);
});
