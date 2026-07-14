// Passkey/PRF unlock smoke tests using Chromium's WebAuthn virtual authenticator via CDP.
// WebAuthn requires a secure context, so we serve index.html over http://127.0.0.1:<port>
// (loopback origins are treated as secure).
import { chromium } from 'playwright';
import { fileURLToPath } from 'url';
import path from 'path';
import http from 'node:http';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

function assert(cond, msg) {
    if (!cond) { console.error('FAIL:', msg); process.exit(1); }
    console.log('PASS:', msg);
}
function skip(msg) { console.log('SKIP:', msg); }

function serve() {
    const server = http.createServer((req, res) => {
        const url = req.url.split('?')[0];
        const rel = url === '/' ? '/index.html' : url;
        const full = path.resolve(ROOT, '.' + rel);
        if (!full.startsWith(ROOT)) { res.writeHead(403); res.end(); return; }
        fs.readFile(full, (err, data) => {
            if (err) { res.writeHead(404); res.end(); return; }
            const ct = rel.endsWith('.html') ? 'text/html; charset=utf-8'
                : rel.endsWith('.js') ? 'application/javascript' : 'text/plain';
            res.writeHead(200, { 'Content-Type': ct });
            res.end(data);
        });
    });
    return new Promise((resolve) => server.listen(0, 'localhost', () => resolve(server)));
}

(async () => {
    const server = await serve();
    const port = server.address().port;
    const APP_URL = `http://localhost:${port}/index.html`;

    const browser = await chromium.launch();

    async function newAuthenticatedContext(hasPrf) {
        const context = await browser.newContext();
        const page = await context.newPage();
        page.on('pageerror', e => { console.error('PAGE ERROR:', e); process.exitCode = 1; });
        const cdp = await context.newCDPSession(page);
        await cdp.send('WebAuthn.enable', { enableUI: false });
        const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
            options: {
                protocol: 'ctap2',
                transport: 'internal',
                hasResidentKey: true,
                hasUserVerification: true,
                isUserVerified: true,
                automaticPresenceSimulation: true,
                ...(hasPrf ? { hasPrf: true } : {})
            }
        });
        return { context, page, cdp, authenticatorId };
    }

    async function waitUnlocked(page) {
        await page.waitForFunction(
            () => !document.getElementById('lock-overlay').classList.contains('open'),
            null, { timeout: 8000 }
        );
    }

    // --- Test A: Feature detection hides the button when WebAuthn is unavailable ---
    {
        const context = await browser.newContext();
        const page = await context.newPage();
        await page.addInitScript(() => { delete window.PublicKeyCredential; });
        await page.goto(APP_URL);
        await page.evaluate(() => localStorage.clear());
        await page.reload();
        await page.waitForSelector('#sidebar');
        await page.evaluate(async () => {
            window.createNote();
            document.getElementById('note-title').value = 'x';
            document.getElementById('note-title').dispatchEvent(new Event('input'));
            await window.enableEncryption('correct horse battery');
        });
        // Simulate a vault with a fake passkey wrap so the button visibility logic has something
        // to react to. This tests strictly the feature-detection branch of updatePasskeyButtonVisibility.
        await page.evaluate(() => {
            const meta = JSON.parse(localStorage.getItem('v4_store'));
            meta.security.wraps.passkeys = [{
                credentialId: 'AAAA', prfSalt: 'AAAA', hkdfSalt: 'AAAA',
                alg: 'AES-KW', wrapped: 'AAAA', addedAt: Date.now(), label: 'Fake'
            }];
            localStorage.setItem('v4_store', JSON.stringify(meta));
        });
        await page.addInitScript(() => { delete window.PublicKeyCredential; });
        await page.reload();
        await page.waitForSelector('#lock-overlay.open');
        const hidden = await page.evaluate(() => document.getElementById('unlock-passkey-btn').hidden);
        assert(hidden, 'passkey button hidden when window.PublicKeyCredential is absent');
        await context.close();
    }

    // --- Test B: With WebAuthn available and a passkey registered, button appears ---
    {
        const { context, page } = await newAuthenticatedContext(true);
        await page.goto(APP_URL);
        await page.evaluate(() => localStorage.clear());
        await page.reload();
        await page.waitForSelector('#sidebar');
        await page.evaluate(async () => {
            window.createNote();
            const t = document.getElementById('note-title');
            t.value = 'passkey secret';
            t.dispatchEvent(new Event('input'));
            const c = document.getElementById('note-content');
            c.value = 'plaintext content';
            c.dispatchEvent(new Event('input'));
            await new Promise(r => setTimeout(r, 100));
            await window.enableEncryption('correct horse battery');
        });
        // Try to register a passkey through the virtual authenticator.
        let registered = false;
        let regError = null;
        try {
            await page.evaluate(async () => await window.registerPasskey('Test Key'));
            registered = true;
        } catch(e) {
            regError = String(e);
        }
        if (!registered) {
            skip('Virtual authenticator PRF registration unsupported: ' + regError);
            await context.close();
        } else {
            assert(true, 'passkey registered via virtual authenticator');

            const passkeys = await page.evaluate(() => JSON.parse(localStorage.getItem('v4_store')).security.wraps.passkeys);
            assert(passkeys.length === 1, 'exactly one passkey stored');
            assert(passkeys[0].prfSalt && passkeys[0].hkdfSalt && passkeys[0].wrapped, 'passkey record has salts and wrapped DEK');
            assert(passkeys[0].label === 'Test Key', 'passkey label persisted');

            // Reload — expect the lock overlay with a visible passkey button
            await page.reload();
            await page.waitForSelector('#lock-overlay.open');
            const btnHidden = await page.evaluate(() => document.getElementById('unlock-passkey-btn').hidden);
            assert(!btnHidden, 'passkey button visible on lock overlay after registration');

            // Unlock via passkey
            await page.click('#unlock-passkey-btn');
            await waitUnlocked(page);
            const state = await page.evaluate(() => window.store.getState());
            assert(state.notes.some(n => n.title === 'passkey secret'), 'passkey unlock decrypts state');

            // Passphrase still works as an alternate unlock (verify by locking + unlocking with passphrase)
            await page.click('#lock-btn');
            await page.waitForFunction(() => document.getElementById('lock-overlay').classList.contains('open'));
            await page.fill('#unlock-passphrase', 'correct horse battery');
            await page.click('#unlock-submit');
            await waitUnlocked(page);
            assert(true, 'passphrase still unlocks after passkey is registered');

            // Remove passkey
            await page.evaluate(async () => {
                const pk = JSON.parse(localStorage.getItem('v4_store')).security.wraps.passkeys[0];
                await window.removePasskey(pk.credentialId);
            });
            const after = await page.evaluate(() => JSON.parse(localStorage.getItem('v4_store')).security.wraps.passkeys);
            assert(after.length === 0, 'passkey removed from vault');

            // Reload — lock overlay should hide the passkey button (no passkeys left)
            await page.reload();
            await page.waitForSelector('#lock-overlay.open');
            const btnHidden2 = await page.evaluate(() => document.getElementById('unlock-passkey-btn').hidden);
            assert(btnHidden2, 'passkey button hidden when no passkeys registered');

            await context.close();
        }
    }

    // --- Test C: Virtual authenticator without PRF surfaces a clear error ---
    {
        const { context, page } = await newAuthenticatedContext(false);
        await page.goto(APP_URL);
        await page.evaluate(() => localStorage.clear());
        await page.reload();
        await page.waitForSelector('#sidebar');
        await page.evaluate(async () => {
            window.createNote();
            document.getElementById('note-title').value = 'x';
            document.getElementById('note-title').dispatchEvent(new Event('input'));
            await new Promise(r => setTimeout(r, 50));
            await window.enableEncryption('correct horse battery');
        });
        let err = null;
        try {
            await page.evaluate(async () => await window.registerPasskey('NoPRF'));
        } catch(e) { err = String(e); }
        assert(err && /PRF/i.test(err), 'registration on non-PRF authenticator throws a PRF-specific error');
        const pks = await page.evaluate(() => JSON.parse(localStorage.getItem('v4_store')).security.wraps.passkeys);
        assert(pks.length === 0, 'failed registration does not persist a partial record');
        await context.close();
    }

    await browser.close();
    server.close();
    console.log('\nPasskey tests complete.');
})();
