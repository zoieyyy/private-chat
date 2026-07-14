#!/usr/bin/env node
// Compute the SHA-256 hash of the executable inline <script> block in index.html and
// update the CSP meta tag's __CSP_SCRIPT_HASH__ placeholder (or an already-embedded hash)
// so the browser will actually execute the script.
//
// Run this whenever the inline <script> block changes. Everything CSP does depends on
// this hash matching the byte-for-byte content the browser sees between <script> and
// </script>. A mismatch by even one whitespace character means the browser silently
// refuses to run the app.
//
// Usage:  node tools/compute-csp-hash.mjs
//
// The script rewrites index.html in place. Idempotent — running twice on unchanged
// content is a no-op.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HTML_PATH = path.resolve(__dirname, '..', 'index.html');

const src = fs.readFileSync(HTML_PATH, 'utf8');

// Strip HTML comments before matching so any text inside comments (which the browser
// treats as non-content) doesn't accidentally look like a script tag.
const stripped = src.replace(/<!--[\s\S]*?-->/g, '');

// The executable script is the one whose opening tag has no attributes at all —
// the JSON data block carries id="app-data" type="application/json".
const re = /<script>([\s\S]*?)<\/script>/;
const m = stripped.match(re);
if (!m) {
    console.error('Could not find bare inline <script> block in index.html');
    process.exit(1);
}
const scriptContent = m[1];

const hash = crypto.createHash('sha256').update(scriptContent, 'utf8').digest('base64');
const cspValue = `sha256-${hash}`;

// Replace either the placeholder or an existing sha256- value inside the CSP meta.
const cspRe = /(script-src[^;"]*?)(?:'__CSP_SCRIPT_HASH__'|'sha256-[A-Za-z0-9+/=]+')/;
if (!cspRe.test(src)) {
    console.error('CSP meta tag placeholder not found. Ensure the meta tag contains __CSP_SCRIPT_HASH__ or an existing sha256- value inside script-src.');
    process.exit(1);
}
const updated = src.replace(cspRe, `$1'${cspValue}'`);

if (updated === src) {
    console.log(`CSP hash already up to date: ${cspValue}`);
} else {
    fs.writeFileSync(HTML_PATH, updated, 'utf8');
    console.log(`Updated CSP script hash: ${cspValue}`);
}
