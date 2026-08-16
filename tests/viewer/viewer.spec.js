// End-to-end harness for the source viewer (site/src/index.html).
//
// The page under test is served intact — not a copy, not instrumented — with
// its three external surfaces intercepted so the run is hermetic and tests
// the working tree:
//   raw.githubusercontent.com/…/src/*.md  →  the local src/*.md bytes
//   esm.sh/*                              →  real CodeMirror, bundled from
//                                            tests/viewer/node_modules (esm-local.js)
//   cdn.jsdelivr.net (marked)             →  the same pinned marked.min.js
// Any other request is a harness hole and fails the test.
//
// What is verified, against the real authored files: the doc model matches an
// independent fence split byte-for-byte, real CodeMirror mounts and highlights
// Python in every code cell, Navigator landmarks and cell headers carry the
// literate `# Name` labels, fence-edge blank lines are display-trimmed while
// the model keeps the exact bytes, and the page's embedded self-tests pass.
//
// Run:  npm ci && npm test
// (On a machine without a Playwright chromium: npx playwright install chromium.)

const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');
const { bundleForUrl } = require('./esm-local');

const ROOT = path.resolve(__dirname, '..', '..');
const VIEWER = path.join(ROOT, 'site', 'src', 'index.html');
const FILES = ['INIT.md', 'SERVER.md', 'SYSTEM.md', 'SHELL.md', 'MAIN.md']; // build.py order
const read = (name) => fs.readFileSync(path.join(ROOT, 'src', name), 'utf8');

/* ── Reference fence split ──────────────────────────────────────────────────
 * An independent implementation of the authored format's one structural rule:
 * a top-level ``` / ~~~ fence is a code cell, everything between fences is a
 * prose cell (surrounding blank lines dropped). The viewer's parse() agreeing
 * with this, on the real files, is what the DOM assertions below establish.
 * An unterminated fence throws — the authored files must not contain one. */
const FENCE_OPEN = /^ {0,3}(`{3,}|~{3,})[ \t]*([^\n]*?)[ \t]*$/;
const FENCE_CLOSE = /^ {0,3}(`{3,}|~{3,})[ \t]*$/;
const bare = (l) => l.replace(/\r?\n$/, '');
const isBlank = (l) => /^[ \t\r]*\n?$/.test(l);
function fenceOpen(l) {
  const m = FENCE_OPEN.exec(bare(l));
  return m && !(m[1][0] === '`' && m[2].includes('`')) ? m : null;
}
function splitKeepNL(s) {
  const out = [];
  let i = 0;
  while (i < s.length) {
    const nl = s.indexOf('\n', i);
    if (nl < 0) { out.push(s.slice(i)); break; }
    out.push(s.slice(i, nl + 1));
    i = nl + 1;
  }
  return out;
}
function splitCells(text, name) {
  const lines = splitKeepNL(text);
  const cells = [];
  let i = 0;
  while (i < lines.length) {
    const m = fenceOpen(lines[i]);
    if (m) {
      const ch = m[1][0], len = m[1].length, lang = m[2].split(/\s+/)[0] || '';
      let j = i + 1;
      const inner = [];
      for (; j < lines.length; j++) {
        const cm = FENCE_CLOSE.exec(bare(lines[j]));
        if (cm && cm[1][0] === ch && cm[1].length >= len) break;
        inner.push(lines[j]);
      }
      if (j === lines.length) throw new Error(`${name}: unterminated fence at line ${i + 1}`);
      cells.push({ type: 'code', lang, body: inner.join('') });
      i = j + 1;
      continue;
    }
    const buf = [];
    while (i < lines.length && !fenceOpen(lines[i])) { buf.push(lines[i]); i++; }
    let s = 0, e = buf.length;
    while (s < e && isBlank(buf[s])) s++;
    while (e > s && isBlank(buf[e - 1])) e--;
    if (e > s) cells.push({ type: 'md', lang: '', body: buf.slice(s, e).join('') });
  }
  return cells;
}

/* The label rules ARE the literate convention the viewer displays: a code
 * cell is named by its first line with the `#` marker stripped (shebangs keep
 * theirs); an md cell by its first line without heading markers; only
 * heading-led md cells are Navigator landmarks. */
const firstLine = (s) => ((s || '').split('\n').find((x) => x.trim()) || '').trim().slice(0, 60);
const cellLabel = (c) =>
  c.type === 'md'
    ? firstLine(c.body).replace(/^#+\s*/, '') || 'Markdown'
    : firstLine(c.body).replace(/^#(?!!)\s*/, '') || '(empty)';
const isLandmark = (c) => c.type === 'code' || /^#{1,6}\s/.test(firstLine(c.body));

/* ── Interception ─────────────────────────────────────────────────────────── */
let escaped; // URLs no handler claimed — must stay empty

test.beforeEach(async ({ page }) => {
  escaped = [];
  await page.addInitScript(() => localStorage.setItem('servette-src:welcomed', '1'));
  // Registered first = matched last: only requests the handlers below decline.
  await page.route('**/*', (route) => {
    escaped.push(route.request().url());
    route.abort();
  });
  await page.route('https://viewer.test/**', (route) => {
    if (new URL(route.request().url()).pathname === '/')
      return route.fulfill({ contentType: 'text/html; charset=utf-8', body: fs.readFileSync(VIEWER, 'utf8') });
    return route.fulfill({ status: 204, body: '' }); // favicon and friends
  });
  await page.route('https://raw.githubusercontent.com/**', (route) => {
    const m = new URL(route.request().url()).pathname.match(/^\/andy-emerson\/Servette\/[^/]+\/src\/([A-Za-z]+\.md)$/);
    if (m && FILES.includes(m[1]))
      return route.fulfill({ contentType: 'text/plain; charset=utf-8', body: read(m[1]) });
    return route.fulfill({ status: 404, body: 'not found' });
  });
  await page.route('https://esm.sh/**', async (route) =>
    route.fulfill({ contentType: 'text/javascript; charset=utf-8', body: await bundleForUrl(route.request().url()) }));
  await page.route('https://cdn.jsdelivr.net/**', (route) =>
    route.fulfill({
      contentType: 'text/javascript; charset=utf-8',
      body: fs.readFileSync(path.join(__dirname, 'node_modules', 'marked', 'marked.min.js'), 'utf8'),
    }));
});

test.afterEach(() => expect(escaped, 'requests escaped the harness').toEqual([]));

async function boot(page) {
  await page.goto('https://viewer.test/');
  await page.waitForFunction(() => window.NB && window.NB.files.length === 5);
}

// The open file's code cells are upgraded in place; done = no fallback <pre>
// left and one CodeMirror editor per code cell.
async function cmReady(page, codeCellCount) {
  await page.waitForFunction(
    (n) =>
      document.querySelectorAll('#nb-scroll pre.code-plain').length === 0 &&
      document.querySelectorAll('#nb-scroll .cm-editor').length === n,
    codeCellCount
  );
}

async function expandInNavigator(page, name) {
  const row = page.locator('#outline-list .list-row.file').filter({ hasText: name });
  if (!(await row.getAttribute('class')).includes('expanded')) await row.click();
}

/* ── Tests ────────────────────────────────────────────────────────────────── */

test('boots on the real sources: doc model matches the reference split, byte-exact', async ({ page }) => {
  await boot(page);
  const got = await page.evaluate(() =>
    window.NB.files.map((f) => ({
      name: f.name,
      error: !!f.error,
      roundTrip: window.NB.serialize(f.doc) === f.raw,
      raw: f.raw,
      cells: f.doc.cells.map((c) => ({ type: c.type, lang: c.lang, body: c.code })),
    }))
  );
  expect(got.map((f) => f.name)).toEqual(FILES);
  for (const f of got) {
    expect(f.error, `${f.name} loaded`).toBe(false);
    expect(f.raw, `${f.name} bytes as authored`).toBe(read(f.name));
    expect(f.roundTrip, `${f.name} serialize(doc) === fetched bytes`).toBe(true);
    expect(f.cells, `${f.name} cells match the reference split`).toEqual(splitCells(read(f.name), f.name));
  }
});

test('real CodeMirror mounts in every code cell and highlights Python', async ({ page }) => {
  await boot(page);
  const codeCells = splitCells(read('INIT.md'), 'INIT.md').filter((c) => c.type === 'code');
  await cmReady(page, codeCells.length);
  const colors = await page.evaluate(() => {
    const probe = (cssColor) => {
      const el = document.createElement('span');
      el.style.color = cssColor;
      document.body.appendChild(el);
      const c = getComputedStyle(el).color;
      el.remove();
      return c;
    };
    const spans = [...document.querySelectorAll('#nb-scroll .cm-line span')];
    const kw = spans.find((s) => s.textContent === 'import');
    const comment = spans.find((s) => /^# \S/.test(s.textContent));
    return {
      keyword: kw && getComputedStyle(kw).color,
      keywordWant: probe('var(--syntax-keyword)'),
      comment: comment && getComputedStyle(comment).fontStyle,
      plainText: probe('var(--text-primary)'),
    };
  });
  expect(colors.keyword, 'an `import` keyword span exists and is colored').toBe(colors.keywordWant);
  expect(colors.keyword).not.toBe(colors.plainText); // the theme really distinguishes it
  expect(colors.comment, 'comments render italic').toBe('italic');
});

test('Navigator landmarks carry the literate names, for every file', async ({ page }) => {
  await boot(page);
  await page.click('#left-activity-bar [data-tab="outline"]');
  for (const name of FILES) {
    await expandInNavigator(page, name);
    const rows = await page.locator('#outline-list .list-row.indent').allTextContents();
    const want = splitCells(read(name), name).filter(isLandmark).map(cellLabel);
    expect(rows, `${name} landmarks`).toEqual(want);
  }
});

test('cell headers pair every fence with its name, for every file', async ({ page }) => {
  await boot(page);
  await page.click('#left-activity-bar [data-tab="outline"]');
  for (const name of FILES) {
    await expandInNavigator(page, name);
    const titles = await page.locator('#nb-scroll .cell .cell-title').allTextContents();
    const badges = await page.locator('#nb-scroll .cell .cell-badge').allTextContents();
    const cells = splitCells(read(name), name);
    expect(titles, `${name} cell titles`).toEqual(cells.map(cellLabel));
    expect(badges, `${name} cell badges`).toEqual(
      cells.map((c) => (c.type === 'md' ? 'Markdown' : (c.lang || 'code').toUpperCase()))
    );
  }
});

test('fence-edge blank lines are display-trimmed; the model keeps the bytes', async ({ page }) => {
  const cells = splitCells(read('INIT.md'), 'INIT.md');
  const codeCells = cells.filter((c) => c.type === 'code');
  const trim = (s) => s.replace(/^\n+/, '').replace(/\n+$/, '');
  // The check must have something to bite on: at least one INIT.md fence
  // carries edge blanks (they are servette.py's inter-block spacing).
  expect(codeCells.some((c) => trim(c.body) !== c.body.replace(/\n$/, ''))).toBe(true);
  await boot(page);
  await cmReady(page, codeCells.length);
  const rendered = await page.$$eval('#nb-scroll .cell', (els) =>
    els
      .filter((el) => el.querySelector('.cm-editor'))
      .map((el) => [...el.querySelectorAll('.cm-line')].map((l) => l.textContent))
  );
  expect(rendered, 'each editor shows the fence body, edge blanks trimmed').toEqual(
    codeCells.map((c) => trim(c.body).split('\n'))
  );
  // ...while the doc model keeps the exact bytes (test 1 proves this for all
  // files; assert the trimmed cells specifically to pin the distinction).
  const modelBodies = await page.evaluate(() =>
    window.NB.files[0].doc.cells.filter((c) => c.type === 'code').map((c) => c.code)
  );
  expect(modelBodies).toEqual(codeCells.map((c) => c.body));
});

test("the page's embedded self-tests pass", async ({ page }) => {
  await boot(page);
  expect(await page.evaluate(() => window.NB.runSelfTests())).toBe(true);
});
