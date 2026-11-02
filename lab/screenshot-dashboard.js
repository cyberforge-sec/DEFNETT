const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({
    headless: true,
    channel: 'chrome', // Gunakan Google Chrome yang sudah terpasang
  });

  const contexts = {};

  // 1920x1080
  contexts['1920'] = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 1,
  });

  // 1366x768
  contexts['1366'] = await browser.newContext({
    viewport: { width: 1366, height: 768 },
    deviceScaleFactor: 1,
  });

  const scenarios = [
    { name: 'overview', path: '/', label: 'Overview (Topology)', wait: 3000 },
    { name: 'patrol', path: '/?patrol=1', label: 'Patrol View', wait: 3000 },
  ];

  for (const scenario of scenarios) {
    for (const [size, ctx] of Object.entries(contexts)) {
      const page = await ctx.newPage();
      await page.goto(`http://127.0.0.1:8090${scenario.path}`, { waitUntil: 'networkidle' });
      if (scenario.name === 'patrol') {
        await page.click('#tab-patrol').catch(() => {});
      }
      await page.waitForTimeout(scenario.wait);
      // Extra wait for canvas initialisation in patrol view
      if (scenario.name === 'patrol') {
        await page.waitForTimeout(2000);
      }
      await page.screenshot({
        path: `screenshot_${scenario.name}_${size}.png`,
        fullPage: true,
      });
      console.log(`✓ ${scenario.label} (${size}) saved`);
      await page.close();
    }
  }

  // Incident demo
  const mainCtx = contexts['1920'];
  const page = await mainCtx.newPage();
  await page.goto('http://127.0.0.1:8090/', { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);

  await page.click('#tab-patrol').catch(() => {});
  await page.waitForTimeout(1000);

  await page.click('#patrol-demo-toggle').catch(() => {});
  await page.waitForTimeout(2000);
  await page.click('#patrol-incident-demo').catch(() => {});
  await page.waitForTimeout(6000);

  await page.screenshot({
    path: `screenshot_incident_1920.png`,
    fullPage: true,
  });
  console.log('✓ Incident (1920) saved');

  // Wait for recovery
  await page.waitForTimeout(15000);
  await page.screenshot({
    path: `screenshot_recovered_1920.png`,
    fullPage: true,
  });
  console.log('✓ Recovered (1920) saved');

  await browser.close();
  console.log('\n=== Semua screenshot selesai ===');
})();