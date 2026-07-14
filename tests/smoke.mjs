// End-to-end smoke test for the encryption flows.
// Uses playwright to drive a real Chromium against index.html served over file://
// so localStorage and BroadcastChannel behave the same as they do for a user.
import { chromium } from 'playwright';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const APP_URL = 'file://' + path.resolve(__dirname, '../index.html');

function assert(cond, msg) {
    if (!cond) { console.error('FAIL:', msg); process.exit(1); }
    console.log('PASS:', msg);
}

async function bootFresh(browser) {
    const context = await browser.newContext();
    const page = await context.newPage();
    page.on('pageerror', e => { console.error('PAGE ERROR:', e); process.exitCode = 1; });
    page.on('console', msg => {
        if (msg.type() === 'error') console.error('CONSOLE ERROR:', msg.text());
    });
    await page.goto(APP_URL);
    await page.waitForLoadState('domcontentloaded');
    return { context, page };
}

async function typeInto(page, selector, text) {
    await page.click(selector);
    await page.fill(selector, text);
}

async function waitUnlocked(page) {
    await page.waitForFunction(
        () => !document.getElementById('lock-overlay').classList.contains('open'),
        null,
        { timeout: 5000 }
    );
}

(async () => {
    const browser = await chromium.launch();

    // --- Test 1: Plain-mode boot works, notes persist ---
    {
        const { context, page } = await bootFresh(browser);
        await page.evaluate(() => localStorage.clear());
        await page.reload();
        await page.waitForSelector('#sidebar');
        // Create a note
        await page.evaluate(() => window.createNote());
        await page.waitForSelector('#note-title');
        await typeInto(page, '#note-title', 'plain hello');
        await typeInto(page, '#note-content', 'plain world');
        await page.waitForTimeout(150);
        const stored = await page.evaluate(() => localStorage.getItem('v4_store'));
        assert(stored && stored.includes('plain hello'), 'plain vault stores plaintext title in localStorage');
        assert(JSON.parse(stored).security?.mode === 'plain', 'plain vault has security.mode=plain');
        await context.close();
    }

    // --- Test 2: Enable encryption, verify ciphertext-only storage ---
    let encryptedVaultSample;
    {
        const { context, page } = await bootFresh(browser);
        await page.evaluate(() => localStorage.clear());
        await page.reload();
        await page.waitForSelector('#sidebar');
        await page.evaluate(() => window.createNote());
        await typeInto(page, '#note-title', 'secret note');
        await typeInto(page, '#note-content', 'top secret content');
        await page.waitForTimeout(100);

        // Trigger enable via API to avoid modal choreography for the first test
        await page.evaluate(async () => await window.enableEncryption('correct horse battery'));
        await page.waitForTimeout(200);

        const stored = await page.evaluate(() => localStorage.getItem('v4_store'));
        const parsed = JSON.parse(stored);
        assert(parsed.security?.mode === 'encrypted', 'vault flips to encrypted');
        assert(parsed.ciphertext && parsed.ciphertext.data, 'vault carries ciphertext');
        assert(!stored.includes('top secret content'), 'plaintext note content not visible in localStorage');
        assert(!stored.includes('secret note'), 'plaintext note title not visible in localStorage');
        assert(parsed.security.kdf.iterations >= 600000, 'PBKDF2 iterations at policy minimum');
        assert(parsed.security.wraps.passphrase?.wrapped, 'passphrase-wrapped DEK stored');
        encryptedVaultSample = stored;
        await context.close();
    }

    // --- Test 3: Reload of encrypted vault shows lock overlay; wrong passphrase rejected ---
    {
        const { context, page } = await bootFresh(browser);
        await page.evaluate((v) => localStorage.setItem('v4_store', v), encryptedVaultSample);
        await page.reload();
        await page.waitForSelector('#lock-overlay.open');
        const bodyLocked = await page.evaluate(() => document.body.classList.contains('locked'));
        assert(bodyLocked, 'body.locked applied when encrypted vault boots');
        const sidebarInert = await page.evaluate(() => document.getElementById('sidebar').hasAttribute('inert'));
        assert(sidebarInert, 'sidebar is inert while locked');

        // Wrong passphrase → error, still locked
        await page.fill('#unlock-passphrase', 'wrong passphrase');
        await page.click('#unlock-submit');
        await page.waitForTimeout(300);
        const err = await page.textContent('#unlock-error');
        assert(err && err.toLowerCase().includes('incorrect'), 'wrong passphrase produces error message');
        const stillLocked = await page.evaluate(() => document.getElementById('lock-overlay').classList.contains('open'));
        assert(stillLocked, 'lock overlay stays open after wrong passphrase');

        // Correct passphrase → unlocked
        await page.fill('#unlock-passphrase', 'correct horse battery');
        await page.click('#unlock-submit');
        await waitUnlocked(page);
        const noteText = await page.textContent('#tree-container');
        assert(noteText.includes('secret note'), 'unlocked note title appears in sidebar');
        await context.close();
    }

    // --- Test 4: Change passphrase, old fails, new works ---
    {
        const { context, page } = await bootFresh(browser);
        await page.evaluate((v) => localStorage.setItem('v4_store', v), encryptedVaultSample);
        await page.reload();
        await page.waitForSelector('#lock-overlay.open');
        await page.fill('#unlock-passphrase', 'correct horse battery');
        await page.click('#unlock-submit');
        await waitUnlocked(page);

        await page.evaluate(async () => await window.changePassphrase('correct horse battery', 'new stronger passphrase'));
        await page.waitForTimeout(200);
        const newVault = await page.evaluate(() => localStorage.getItem('v4_store'));

        // Reload, should still be encrypted
        await page.reload();
        await page.waitForSelector('#lock-overlay.open');

        // Old passphrase now fails
        await page.fill('#unlock-passphrase', 'correct horse battery');
        await page.click('#unlock-submit');
        await page.waitForTimeout(300);
        const stillLocked = await page.evaluate(() => document.getElementById('lock-overlay').classList.contains('open'));
        assert(stillLocked, 'old passphrase no longer works');

        // New passphrase works
        await page.fill('#unlock-passphrase', 'new stronger passphrase');
        await page.click('#unlock-submit');
        await waitUnlocked(page);
        assert(true, 'new passphrase unlocks after change');
        await context.close();
    }

    // --- Test 5: Disable encryption returns to plaintext ---
    {
        const { context, page } = await bootFresh(browser);
        await page.evaluate((v) => localStorage.setItem('v4_store', v), encryptedVaultSample);
        await page.reload();
        await page.waitForSelector('#lock-overlay.open');
        await page.fill('#unlock-passphrase', 'correct horse battery');
        await page.click('#unlock-submit');
        await waitUnlocked(page);
        await page.evaluate(async () => await window.disableEncryption('correct horse battery'));
        await page.waitForTimeout(200);
        const stored = await page.evaluate(() => localStorage.getItem('v4_store'));
        const parsed = JSON.parse(stored);
        assert(parsed.security.mode === 'plain', 'vault flipped back to plain');
        assert(stored.includes('secret note'), 'plaintext title visible again after disable');
        await context.close();
    }

    // --- Test 6: Modal focus trap + Escape cancels folder delete ---
    {
        const { context, page } = await bootFresh(browser);
        await page.evaluate(() => localStorage.clear());
        await page.reload();
        await page.waitForSelector('#sidebar');
        // Create a second folder so we can delete one
        await page.evaluate(() => window.createFolder());
        await page.waitForTimeout(100);
        // Click the ✕ on the first folder header
        await page.evaluate(() => {
            const btn = document.querySelector('.folder-header .icon-btn.delete');
            btn.click();
        });
        await page.waitForSelector('.modal-dialog[role="alertdialog"]');
        // The initial focus should NOT be on a danger button
        const focusedKind = await page.evaluate(() => document.activeElement.className);
        assert(!focusedKind.includes('danger'), 'destructive button is not auto-focused');
        // Escape cancels
        await page.keyboard.press('Escape');
        await page.waitForSelector('.modal-dialog', { state: 'detached', timeout: 2000 });
        const folderCount = await page.evaluate(() => document.querySelectorAll('.folder-header').length);
        assert(folderCount === 2, 'Escape cancels folder delete');
        await context.close();
    }

    // --- Test 7: Export contains encrypted payload only ---
    {
        const { context, page } = await bootFresh(browser);
        await page.evaluate((v) => localStorage.setItem('v4_store', v), encryptedVaultSample);
        await page.reload();
        await page.waitForSelector('#lock-overlay.open');
        await page.fill('#unlock-passphrase', 'correct horse battery');
        await page.click('#unlock-submit');
        await waitUnlocked(page);

        const exportedHtml = await page.evaluate(async () => {
            const payload = await window.buildVaultPayload(window.store.getState());
            return JSON.stringify(payload);
        });
        assert(!exportedHtml.includes('top secret content'), 'exported payload does not contain plaintext');
        assert(exportedHtml.includes('ciphertext'), 'exported payload carries ciphertext field');
        await context.close();
    }

    await browser.close();
    console.log('\nAll smoke tests passed.');
})();
