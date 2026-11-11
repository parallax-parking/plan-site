// Passphrase gate for the deployed dashboard. Replaces ../data/bundle.js:
// fetches bundle.enc.json, asks for the passphrase once, decrypts in the
// browser (PBKDF2-SHA256 -> AES-256-GCM, matching plan/deploy/encrypt.mjs),
// then hands the bundle to window.renderPlan. Nothing is sent anywhere.
(function () {
  'use strict';
  const enc = new TextEncoder(), dec = new TextDecoder();
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const REMEMBER_KEY = 'switchboard.passphrase';

  async function deriveKey(passphrase, salt, iter) {
    const base = await crypto.subtle.importKey('raw', enc.encode(passphrase.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, base,
      { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  }
  async function decrypt(envelope, passphrase) {
    const key = await deriveKey(passphrase, unb64(envelope.salt), envelope.iter);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(envelope.iv) }, key, unb64(envelope.ct));
    return JSON.parse(dec.decode(pt));
  }

  const app = document.getElementById('app');
  const style = document.createElement('style');
  style.textContent = `
    .gate { max-width: 420px; margin: 12vh auto 0; background: var(--surface); border: 1px solid var(--line); border-radius: 6px; padding: 26px 24px; }
    .gate h1 { font-family: var(--font-display); font-size: 22px; margin: 0 0 6px; }
    .gate p { color: var(--ink-2); margin: 0 0 16px; font-size: 14px; }
    .gate label { display: block; font-size: 12px; color: var(--ink-2); margin-bottom: 6px; }
    .gate input[type=password] { width: 100%; font: inherit; font-family: var(--font-mono); padding: 9px 10px; border: 1px solid var(--line); border-radius: 4px; background: var(--bg); color: var(--ink); }
    .gate .row { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 12px; flex-wrap: wrap; }
    .gate .row label { display: inline-flex; align-items: center; gap: 6px; margin: 0; font-size: 13px; }
    .gate button { font: inherit; font-weight: 600; background: var(--ink); color: var(--bg); border: 0; border-radius: 4px; padding: 8px 16px; cursor: pointer; }
    .gate button[disabled] { opacity: .6; cursor: default; }
    .gate .err { color: var(--crit); font-size: 13px; margin-top: 10px; min-height: 1.2em; }
  `;
  document.head.append(style);

  app.innerHTML = '';
  const gate = document.createElement('form');
  gate.className = 'gate';
  gate.innerHTML = `
    <h1>Switchboard</h1>
    <p>This page is encrypted. Enter the passphrase to decrypt it in your browser.</p>
    <label for="pp">Passphrase</label>
    <input type="password" id="pp" name="pp" autocomplete="current-password" autofocus required>
    <div class="row">
      <label><input type="checkbox" id="remember" name="remember"> Remember on this device</label>
      <button type="submit" id="unlock">Unlock</button>
    </div>
    <div class="err" id="err" role="alert"></div>`;
  app.append(gate);
  const pp = gate.querySelector('#pp'), remember = gate.querySelector('#remember'), btn = gate.querySelector('#unlock'), err = gate.querySelector('#err');

  let envelopePromise = fetch('bundle.enc.json', { cache: 'no-store' }).then(r => {
    if (!r.ok) throw new Error(`bundle.enc.json: HTTP ${r.status}`);
    return r.json();
  });

  async function unlock(passphrase, fromStorage) {
    btn.disabled = true; err.textContent = fromStorage ? 'Decrypting…' : 'Deriving key…';
    try {
      const envelope = await envelopePromise;
      const bundle = await decrypt(envelope, passphrase);
      if (remember.checked) { try { localStorage.setItem(REMEMBER_KEY, passphrase); } catch (e) { /* ignore */ } }
      style.remove();
      window.PLAN_BUNDLE = bundle;
      window.renderPlan(bundle);
    } catch (e) {
      btn.disabled = false;
      if (fromStorage) { try { localStorage.removeItem(REMEMBER_KEY); } catch (_) { /* ignore */ } }
      err.textContent = /HTTP|fetch/i.test(String(e.message)) ? `Could not load the data file (${e.message}).` : 'That passphrase did not decrypt the page.';
      pp.focus(); pp.select();
    }
  }

  gate.addEventListener('submit', ev => { ev.preventDefault(); if (pp.value) unlock(pp.value, false); });

  let saved = null;
  try { saved = localStorage.getItem(REMEMBER_KEY); } catch (e) { /* ignore */ }
  if (saved) { remember.checked = true; pp.value = saved; unlock(saved, true); }
})();
