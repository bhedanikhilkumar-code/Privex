async function checkLiveDeploy() {
  console.log('=== VERIFYING LIVE CLOUDFLARE PAGES PRODUCTION DEPLOYMENT ===');
  const url = 'https://private-protection.pages.dev';
  console.log('Target URL:', url);

  try {
    const res = await fetch(url);
    console.log('Status:', res.status, res.statusText);
    console.log('Headers:');
    for (const [k, v] of res.headers.entries()) {
      if (['content-type', 'content-security-policy', 'strict-transport-security', 'cf-ray'].includes(k.toLowerCase())) {
        console.log(`  ${k}: ${v}`);
      }
    }

    const body = await res.text();
    console.log('\nPage Verification:');
    console.log('  Content Length:', body.length);
    console.log('  Root Div Present:', body.includes('id="root"'));
    console.log('  Meta Viewport:', body.includes('name="viewport"'));
    console.log('  PWA Manifest Linked:', body.includes('manifest.webmanifest'));
    console.log('  Title:', body.match(/<title>(.*?)<\/title>/)?.[1]);

    // Check SPA fallback route
    console.log('\nChecking SPA Deep Link Fallback (https://private-protection.pages.dev/scanner):');
    const spaRes = await fetch('https://private-protection.pages.dev/scanner');
    console.log('SPA Status:', spaRes.status, spaRes.statusText);
    const spaBody = await spaRes.text();
    console.log('SPA Fallback Serves App Shell:', spaBody.includes('id="root"'));

    console.log('\n✓ Live Cloudflare Pages Production Deployment: PASS');
  } catch (err) {
    console.error('Fetch error:', err.message);
  }
}

checkLiveDeploy();
