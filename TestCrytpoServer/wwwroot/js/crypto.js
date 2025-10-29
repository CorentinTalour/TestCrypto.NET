// ==============================
// Helpers DOM-safe (le MP reste côté navigateur)
// ==============================

/**
 * Lit le mot de passe maître depuis un <input> et génère les paramètres
 * de création d’un vault (salt + verifier). Le mot de passe ne sort jamais.
 */
export async function createVaultVerifierFromInput(inputId, iterations = 600000) {
    const pwd = document.getElementById(inputId)?.value ?? "";
    return await createVaultVerifier(pwd, iterations);
}

/**
 * Ouvre un vault existant en lisant le mot de passe maître depuis un <input>.
 * Vérifie côté serveur (envoi du verifier seulement), puis garde la clé AES en RAM.
 */
export async function openVaultFromInput(vaultId, inputId) {
    const pwd = document.getElementById(inputId)?.value ?? "";
    return await openVault(vaultId, pwd);
}

// ==============================
// UTILS ENCODAGE / DÉCODAGE
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
// GÉNÉRATION & VÉRIFICATION DU VAULT
// ==============================

/**
 * Création d’un vault côté client :
 * - génère un salt
 * - dérive 64 octets via PBKDF2-SHA256
 * - verifier = SHA-256(premiers 32 octets)
 * - ⛔ n’expose PAS la moitié “clé” (derniers 32 octets)
 */
export async function createVaultVerifier(password, iterations = 600000) {
    const vaultSalt = crypto.getRandomValues(new Uint8Array(16));
    const vaultSaltB64 = b64(vaultSalt);

    // deriveBits pour fabriquer le verifier
    const pwKey = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt: vaultSalt, iterations },
        pwKey,
        512
    );

    const b = new Uint8Array(bits);
    const verifyPart = b.subarray(0, 32); // vue sans copie
    const verifierHash = await crypto.subtle.digest("SHA-256", verifyPart);

    // best-effort wipe (JS ne garantit pas, mais c’est mieux que rien)
    b.fill(0);

    return {
        vaultSaltB64,
        iterations,
        verifierB64: b64(verifierHash) // à stocker en BDD
    };
}

/**
 * Recalcule uniquement le verifier depuis password + salt/iterations.
 * ⛔ N’expose pas de “key material”.
 */
export async function computeVerifierFromPassword(password, vaultSaltB64, iterations = 600000) {
    const pwKey = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt: b64d(vaultSaltB64), iterations },
        pwKey,
        512
    );
    const b = new Uint8Array(bits);
    const verifyPart = b.subarray(0, 32);
    const verifierHash = await crypto.subtle.digest("SHA-256", verifyPart);
    b.fill(0);
    return { verifierB64: b64(verifierHash) };
}

// ==============================
// GESTION DU VAULT EN RAM (clé AES non-extractable)
// ==============================

let currentVault = { id: null, key: /** @type {CryptoKey|null} */(null) };

/**
 * Ouvre un vault :
 * - récupère salt/iterations
 * - calcule verifier (deriveBits) et le poste à /check
 * - si ok, dérive directement la CryptoKey AES-GCM non-extractable (deriveKey)
 *   → la clé reste en RAM (currentVault.key) et n’est jamais exportée
 */
export async function openVault(vaultId, password) {
    const p = await (await fetch(`/api/vaults/${vaultId}/params`)).json(); // { vaultSaltB64, iterations }

    // 1) Verifier
    const { verifierB64 } = await computeVerifierFromPassword(password, p.vaultSaltB64, p.iterations);
    const check = await (await fetch(`/api/vaults/${vaultId}/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ verifierB64 })
    })).json();

    if (!check.ok) return { ok: false, error: "Mot de passe maître invalide." };

    // 2) Clé AES-GCM non-extractable via deriveKey (aucun encKeyMaterial n’est exposé)
    const pwKey = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);
    const aesKey = await crypto.subtle.deriveKey(
        { name: "PBKDF2", hash: "SHA-256", salt: b64d(p.vaultSaltB64), iterations: p.iterations },
        pwKey,
        { name: "AES-GCM", length: 256 },
        false, // non-extractable
        ["encrypt", "decrypt"]
    );

    currentVault = { id: vaultId, key: aesKey };
    return { ok: true };
}

// ==============================
// CHIFFREMENT / DÉCHIFFREMENT DES ENTRÉES
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
    return new TextDecoder().decode(pt);
}

/**
 * Chiffre une nouvelle entrée (name/password/url/notes) via la clé du vault.
 * Retourne des champs Base64 (cipher, tag, iv) pour un POST JSON.
 */
export async function encryptEntryForOpenVault() {
    if (!currentVault.key) throw new Error("Vault non ouvert");
    const get = id => document.getElementById(id)?.value ?? "";
    const name = get("name"), pwd = get("pwd"), url = get("url"), notes = get("notes");

    // AAD minimale par champ (tu peux lier au vaultId si tu veux)
    const p  = await encFieldWithVaultKey(pwd,   "field:password");
    const n  = await encFieldWithVaultKey(name,  "field:name");
    const u  = await encFieldWithVaultKey(url,   "field:url");
    const no = await encFieldWithVaultKey(notes, "field:notes");

    return {
        cipherPasswordB64: b64(p.cipher), tagPasswordB64: b64(p.tag), ivPasswordB64: b64(p.iv),
        cipherNameB64:     b64(n.cipher), tagNameB64:     b64(n.tag), ivNameB64:     b64(n.iv),
        cipherUrlB64:      b64(u.cipher), tagUrlB64:      b64(u.tag), ivUrlB64:      b64(u.iv),
        cipherNotesB64:    b64(no.cipher),tagNotesB64:    b64(no.tag),ivNotesB64:    b64(no.iv)
    };
}

/**
 * Déchiffre une entrée (venue chiffrée de l’API) côté client.
 */
export async function decryptVaultEntry(record) {
    const out = {};
    out.password = await decFieldWithVaultKey(b64d(record.cipherPasswordB64), b64d(record.tagPasswordB64), b64d(record.ivPasswordB64), "field:password");
    out.name     = await decFieldWithVaultKey(b64d(record.cipherNameB64),     b64d(record.tagNameB64),     b64d(record.ivNameB64),     "field:name");
    out.url      = await decFieldWithVaultKey(b64d(record.cipherUrlB64),      b64d(record.tagUrlB64),      b64d(record.ivUrlB64),      "field:url");
    out.notes    = await decFieldWithVaultKey(b64d(record.cipherNotesB64),    b64d(record.tagNotesB64),    b64d(record.ivNotesB64),    "field:notes");
    return out;
}

// ==============================
// Rendu DOM côté client
// ==============================

/**
 * Rend la liste des entrées dans #vault-list après déchiffrement côté client.
 */
export async function renderVaultEntries(records) {
    const list = document.getElementById("vault-list");
    if (!list) return;                  // garde-fou DOM
    list.innerHTML = "";

    if (!records || records.length === 0) {
        list.innerHTML = "<em>Aucune entrée.</em>";
        return;
    }

    for (const rec of records) {
        const dec = await decryptVaultEntry(rec);
        const item = document.createElement("div");
        item.className = "entry";
        item.style.marginBottom = "1rem";
        item.innerHTML = `
      <strong>${dec.name}</strong><br>
      <div>Mot de passe : ${dec.password}</div>
      <div>URL : ${dec.url}</div>
      <div>Notes : ${dec.notes}</div>
    `;
        list.appendChild(item);
    }
}

/** Vide le conteneur #vault-list (ex: quand on ferme le vault). */
export function clearVaultList() {
    const list = document.getElementById("vault-list");
    if (list) list.innerHTML = "";
}