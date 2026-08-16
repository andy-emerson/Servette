// A local stand-in for esm.sh, for the viewer e2e harness. The viewer's import
// map resolves its five CodeMirror specifiers to https://esm.sh/<pkg>@<major>;
// the Playwright spec intercepts every esm.sh request and answers with a bundle
// built here from tests/viewer/node_modules — so the tests exercise the real
// packages with no network.
//
// esm.sh's one load-bearing semantic is reproduced: each package is served as
// its OWN module, its bare imports left as further esm.sh URLs (intercepted in
// turn). One module instance per package is what keeps CodeMirror facet and
// lezer Tag identities shared across @codemirror/* — inlining the shared deps
// into each bundle instead would break highlighting silently.

const esbuild = require('esbuild');
const fs = require('fs');
const path = require('path');

const NODE_MODULES = path.join(__dirname, 'node_modules');
const cache = new Map(); // specifier -> Promise<string>

// The viewer's own import map, read from the page: a browser module's identity
// is its URL, so a dependency on one of the mapped specifiers must be
// rewritten to the EXACT URL the map resolves it to — an unversioned
// https://esm.sh/@codemirror/state next to the map's …/state@6 would load the
// package twice and break every instanceof check inside CodeMirror.
const IMPORT_MAP = (() => {
  const html = fs.readFileSync(path.join(__dirname, '..', '..', 'site', 'src', 'index.html'), 'utf8');
  const m = html.match(/<script type="importmap">\s*([\s\S]*?)<\/script>/);
  return m ? JSON.parse(m[1]).imports : {};
})();

// "@scope/name/sub" -> {pkg:"@scope/name", sub:"sub"}; "name" -> {pkg:"name", sub:""}
function splitSpecifier(spec) {
  const parts = spec.split('/');
  const pkg = spec.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
  return { pkg, sub: parts.slice(pkg.startsWith('@') ? 2 : 1).join('/') };
}

// The URL path the import map (and our rewritten imports) use, version tag
// tolerated and dropped: "/@codemirror/view@6" -> "@codemirror/view".
function specifierForUrl(url) {
  const spec = decodeURIComponent(new URL(url).pathname).replace(/^\/+/, '');
  const { pkg, sub } = splitSpecifier(spec);
  const bare = pkg.replace(/(.)@[^@/]*$/, '$1'); // strip a trailing @version, not a scope's @
  return bare + (sub ? '/' + sub : '');
}

// The package's ESM entry file, via its exports map (import condition), with
// module/main fallbacks — require.resolve() would pick the CJS side.
function entryFile(spec) {
  const { pkg, sub } = splitSpecifier(spec);
  const dir = path.join(NODE_MODULES, pkg);
  const meta = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  const key = sub ? './' + sub : '.';
  let target = meta.exports ? meta.exports[key] : undefined;
  while (target && typeof target === 'object') {
    target = target.import ?? target.browser ?? target.default;
  }
  if (!target && !sub) target = meta.module || meta.main || 'index.js';
  if (!target) throw new Error(`no ESM entry for ${spec}`);
  return path.join(dir, target);
}

// Bundle one package as ESM: its own files inlined, every bare import left
// external as an absolute esm.sh URL for the interceptor to serve next.
function bundle(spec) {
  if (cache.has(spec)) return cache.get(spec);
  const job = esbuild
    .build({
      entryPoints: [entryFile(spec)],
      bundle: true,
      format: 'esm',
      write: false,
      logLevel: 'silent',
      plugins: [
        {
          name: 'deps-via-esm-sh',
          setup(build) {
            build.onResolve({ filter: /^[^./]/ }, (args) => ({
              path: IMPORT_MAP[args.path] || 'https://esm.sh/' + args.path,
              external: true,
            }));
          },
        },
      ],
    })
    .then((r) => r.outputFiles[0].text);
  cache.set(spec, job);
  return job;
}

module.exports = { bundleForUrl: (url) => bundle(specifierForUrl(url)) };
