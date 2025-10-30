// ==============================
// Helpers DOM-safe (le MP reste côté navigateur)
// ==============================

/**
 * Création d’un vault via l’API :
 * - envoie le MP en clair (cours)
 * - l’API génère sel + hash (PBKDF2) et stocke
 * - renvoie { vaultId, vaultSaltB64, iterations }
 */
export async function createVaultVerifierFromInput(inputId, iterations = 600000) {
    const password = document.getElementById(inputId)?.value ?? "";
    const res = await fetch("/api/vaults", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password, iterations })
    });
    if (!res.ok) throw new Error("Création du vault échouée");
    return await res.json(); // { vaultId, vaultSaltB64, iterations }
}

/**
 * Ouvre un vault existant :
 * - GET /params → {vaultSaltB64, iterations}
 * - POST /check {password} → l’API vérifie le MP (PBKDF2 côté serveur)
 * - si ok → deriveKey PBKDF2→AES-GCM(256) non-extractable, stockée en RAM
 * - arme l’auto-lock
 */
export async function openVault(vaultId, password, autoLockMs = 300000) {
    // 1) paramètres pour dériver la clé AES localement
    const p = await (await fetch(`/api/vaults/${vaultId}/params`)).json();

    // 2) vérification côté serveur (le MP est envoyé en clair – exigence du cours)
    const check = await (await fetch(`/api/vaults/${vaultId}/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password })
    })).json();

    if (!check.ok) return { ok: false, error: "Mot de passe maître invalide." };

    // 3) dérivation locale de la clé AES (non-extractable)
    const pwKey = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);
    const aesKey = await crypto.subtle.deriveKey(
        { name: "PBKDF2", hash: "SHA-256", salt: b64d(p.vaultSaltB64), iterations: p.iterations },
        pwKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );

    currentVault = { id: vaultId, key: aesKey };
    _autoLockMsDefault = autoLockMs || 300000;
    _armAutoLock(_autoLockMsDefault);
    return { ok: true };
}

/**
 * Ouvre un vault en lisant le MP depuis un <input>.
 * Efface visuellement le champ après usage.
 */
export async function openVaultFromInput(vaultId, inputId, autoLockMs = 300000) {
    const pwd = document.getElementById(inputId)?.value ?? "";
    const res = await openVault(vaultId, pwd, autoLockMs);
    const el = document.getElementById(inputId);
    if (el) el.value = "";
    return res;
}

// ==============================
// Encodage / décodage
// ==============================

const enc = new TextEncoder();
const b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const TAG_BYTES = 16;

function splitCtAndTag(buf) {
    const u = new Uint8Array(buf);
    return { cipher: u.slice(0, u.length - TAG_BYTES), tag: u.slice(u.length - TAG_BYTES) };
}
function joinCtAndTag(cipherU8, tagU8) {
    const out = new Uint8Array(cipherU8.length + tagU8.length);
    out.set(cipherU8, 0);
    out.set(tagU8, cipherU8.length);
    return out.buffer;
}

// ==============================
// Gestion du vault en RAM (clé AES non-extractable) + auto-lock
// ==============================

let currentVault = { id: null, key: /** @type {CryptoKey|null} */(null) };
let _autoLockTimer = /** @type {ReturnType<typeof setTimeout>|null} */ (null);
let _autoLockMsDefault = 300000; // 5 min par défaut

function _clearAutoLock() {
    if (_autoLockTimer) { clearTimeout(_autoLockTimer); _autoLockTimer = null; }
}
function _armAutoLock(ms) {
    _clearAutoLock();
    _autoLockTimer = setTimeout(() => lockNow(), ms);
}

/** Verrouille immédiatement (oublie la clé en RAM) */
export function lockNow() {
    currentVault = { id: null, key: null };
    _clearAutoLock();
    clearVaultList();
}

/** Reset le timer d’auto-lock (à appeler sur toute interaction sensible) */
export function touchVault() {
    if (currentVault.key) _armAutoLock(_autoLockMsDefault);
}

// ==============================
// Chiffrement / déchiffrement des entrées
// ==============================

async function encFieldWithVaultKey(text, aad) {
    if (!currentVault.key) throw new Error("Vault non ouvert");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ctFull = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: aad ? enc.encode(aad) : undefined },
        currentVault.key,
        enc.encode(text ?? "")
    );
    const { cipher, tag } = splitCtAndTag(ctFull);
    touchVault();
    return { cipher, tag, iv };
}

async function decFieldWithVaultKey(cipherU8, tagU8, ivU8, aad) {
    if (!currentVault.key) throw new Error("Vault non ouvert");
    const full = joinCtAndTag(cipherU8, tagU8);
    const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivU8, additionalData: aad ? enc.encode(aad) : undefined },
        currentVault.key,
        full
    );
    touchVault();
    return new TextDecoder().decode(pt);
}

/*
 * Chiffre une nouvelle entrée (DOM → JSON Base64).
 * AAD liée au contexte (vault + type de champ) pour “bind” le ciphertext.
 */
export async function encryptEntryForOpenVault() {
    if (!currentVault.key) throw new Error("Vault non ouvert");
    const get = id => document.getElementById(id)?.value ?? "";
    const name = get("name"), pwd = get("pwd"), url = get("url"), notes = get("notes");

    const ns = `vault:${currentVault.id}`;

    const p  = await encFieldWithVaultKey(pwd,   `${ns}|field:password`);
    const n  = await encFieldWithVaultKey(name,  `${ns}|field:name`);
    const u  = await encFieldWithVaultKey(url,   `${ns}|field:url`);
    const no = await encFieldWithVaultKey(notes, `${ns}|field:notes`);

    return {
        cipherPasswordB64: b64(p.cipher), tagPasswordB64: b64(p.tag), ivPasswordB64: b64(p.iv),
        cipherNameB64:     b64(n.cipher), tagNameB64:     b64(n.tag), ivNameB64:     b64(n.iv),
        cipherUrlB64:      b64(u.cipher), tagUrlB64:      b64(u.tag), ivUrlB64:      b64(u.iv),
        cipherNotesB64:    b64(no.cipher),tagNotesB64:    b64(no.tag),ivNotesB64:    b64(no.iv)
    };
}

/** Déchiffre une entrée (API → clair côté client). */
export async function decryptVaultEntry(record) {
    const ns = `vault:${currentVault.id}`;
    const out = {};
    out.password = await decFieldWithVaultKey(b64d(record.cipherPasswordB64), b64d(record.tagPasswordB64), b64d(record.ivPasswordB64), `${ns}|field:password`);
    out.name     = await decFieldWithVaultKey(b64d(record.cipherNameB64),     b64d(record.tagNameB64),     b64d(record.ivNameB64),     `${ns}|field:name`);
    out.url      = await decFieldWithVaultKey(b64d(record.cipherUrlB64),      b64d(record.tagUrlB64),      b64d(record.ivUrlB64),      `${ns}|field:url`);
    out.notes    = await decFieldWithVaultKey(b64d(record.cipherNotesB64),    b64d(record.tagNotesB64),    b64d(record.ivNotesB64),    `${ns}|field:notes`);
    return out;
}

// ==============================
// Rendu DOM (sans innerHTML sur valeurs sensibles) + auto-lock touch
// ==============================

export async function renderVaultEntries(records) {
    const list = document.getElementById("vault-list");
    if (!list) return;
    list.textContent = "";

    if (!records || records.length === 0) {
        const em = document.createElement("em");
        em.textContent = "Aucune entrée.";
        list.appendChild(em);
        return;
    }

    for (const rec of records) {
        const dec = await decryptVaultEntry(rec);

        const wrap = document.createElement("div");
        wrap.className = "entry";
        wrap.style.marginBottom = "1rem";

        const name = document.createElement("strong");
        name.textContent = dec.name;

        const pwd = document.createElement("div");
        pwd.textContent = `Mot de passe : ${dec.password}`;

        const url = document.createElement("div");
        url.textContent = `URL : ${dec.url}`;

        const notes = document.createElement("div");
        notes.textContent = `Notes : ${dec.notes}`;

        wrap.appendChild(name);
        wrap.appendChild(document.createElement("br"));
        wrap.appendChild(pwd);
        wrap.appendChild(url);
        wrap.appendChild(notes);
        list.appendChild(wrap);
    }

    touchVault();
}

export function clearVaultList() {
    const list = document.getElementById("vault-list");
    if (list) list.textContent = "";
}