// Playwright config for the viewer e2e harness. Chromium only — the harness
// verifies the viewer's behavior, not browser compatibility. Uses a
// pre-provisioned chromium when one exists (CI containers ship one at
// /opt/pw-browsers); otherwise Playwright's own install is used
// (`npx playwright install chromium` once per machine).

const fs = require('fs');
const { defineConfig } = require('@playwright/test');

const provisioned = '/opt/pw-browsers/chromium';

module.exports = defineConfig({
  testDir: __dirname,
  testMatch: '*.spec.js',
  reporter: 'list',
  timeout: 60_000,
  use: {
    launchOptions: fs.existsSync(provisioned) ? { executablePath: provisioned } : {},
  },
});
