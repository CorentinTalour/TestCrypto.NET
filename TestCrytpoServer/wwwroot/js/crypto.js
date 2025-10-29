// ==============================
// Helpers DOM-safe (le MP reste côté navigateur)
// ==============================

/**
 * Lit le mot de passe maître depuis un <input> (par son id) et
 * génère les paramètres de création d’un vault (salt + verifier).
 * ⚠️ Le mot de passe n’est jamais renvoyé, seulement le dérivé.
 * @param {string} inputId - id de l’input password dans le DOM.
 * @param {number} [iterations=600000] - coût PBKDF2.
 * @returns {Promise<{vaultSaltB64:string, iterations:number, verifierB64:string, encKeyMaterialB64:string}>}
 */
export async function createVaultVerifierFromInput(inputId, iterations = 600000) {
    const pwd = document.getElementById(inputId)?.value ?? "";
    return await createVaultVerifier(pwd, iterations);
}

/**
 * Ouvre un vault existant en lisant le mot de passe maître depuis un <input>.
 * Vérifie côté serveur (envoi du verifier seulement), puis garde la clé AES en RAM.
 * @param {number} vaultId - identifiant du vault.
 * @param {string} inputId - id de l’input password dans le DOM.
 * @returns {Promise<{ok:boolean, error?:string}>}
 */
export async function openVaultFromInput(vaultId, inputId) {
    const pwd = document.getElementById(inputId)?.value ?? "";
    return await openVault(vaultId, pwd);
}

// ==============================
// UTILS ENCODAGE / DÉCODAGE
// ==============================

const enc = new TextEncoder();

/** Convertit un ArrayBuffer/TypedArray en Base64 (pour transport/stockage JSON). */
const b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));

/** Convertit une chaîne Base64 en Uint8Array (pour WebCrypto). */
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

/** Longueur du tag d’authentification GCM (16 octets = 128 bits). */
const TAG_BYTES = 16;

/**
 * Sépare le buffer [cipher || tag] retourné par SubtleCrypto.encrypt
 * en deux vues : { cipher, tag }.
 * @param {ArrayBuffer} buf
 * @returns {{cipher:Uint8Array, tag:Uint8Array}}
 */
function splitCtAndTag(buf) {
    const u = new Uint8Array(buf);
    return { cipher: u.slice(0, u.length - TAG_BYTES), tag: u.slice(u.length - TAG_BYTES) };
}

/**
 * Recolle cipher et tag pour SubtleCrypto.decrypt (attend [cipher || tag]).
 * @param {Uint8Array} cipherU8
 * @param {Uint8Array} tagU8
 * @returns {ArrayBuffer}
 */
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
 * Prépare la création d’un vault côté client :
 * - génère un salt (vaultSalt)
 * - dérive 64 octets via PBKDF2-SHA256 (iterations)
 * - split: 32o pour le verifier (après SHA-256), 32o pour encKeyMaterial (clé AES dérivable)
 * @param {string} password - mot de passe maître.
 * @param {number} [iterations=600000] - coût PBKDF2.
 * @returns {Promise<{vaultSaltB64:string, iterations:number, verifierB64:string, encKeyMaterialB64:string}>}
 */
export async function createVaultVerifier(password, iterations = 600000) {
    const vaultSalt = crypto.getRandomValues(new Uint8Array(16));
    const vaultSaltB64 = b64(vaultSalt);

    const pwKey = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt: vaultSalt, iterations },
        pwKey,
        512
    );
    const b = new Uint8Array(bits);
    const verifyPart = b.slice(0, 32);
    const encKeyMaterial = b.slice(32, 64);

    const verifierHash = await crypto.subtle.digest("SHA-256", verifyPart);

    return {
        vaultSaltB64,
        iterations,
        verifierB64: b64(verifierHash),     // à stocker en BDD (pour check)
        encKeyMaterialB64: b64(encKeyMaterial) // à garder en RAM côté client
    };
}

/**
 * Recalcule (à l’ouverture) le verifierB64 et encKeyMaterialB64
 * à partir du password + salt/iterations stockés en BDD.
 * @param {string} password
 * @param {string} vaultSaltB64
 * @param {number} [iterations=600000]
 * @returns {Promise<{verifierB64:string, encKeyMaterialB64:string}>}
 */
export async function computeVerifierFromPassword(password, vaultSaltB64, iterations = 600000) {
    const pwKey = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt: b64d(vaultSaltB64), iterations },
        pwKey,
        512
    );
    const b = new Uint8Array(bits);
    const verifyPart = b.slice(0, 32);
    const encKeyMaterial = b.slice(32, 64);
    const verifierHash = await crypto.subtle.digest("SHA-256", verifyPart);
    return { verifierB64: b64(verifierHash), encKeyMaterialB64: b64(encKeyMaterial) };
}

// ==============================
// GESTION DU VAULT EN RAM (clé AES)
// ==============================

/** État courant du vault ouvert : id + CryptoKey AES-GCM non exportable. */
let currentVault = { id: null, key: null };

/**
 * Importe une clé AES-GCM non exportable depuis encKeyMaterial (32o).
 * @param {string} encKeyMaterialB64
 * @returns {Promise<CryptoKey>}
 */
async function deriveEncKeyFromEncKeyMaterial(encKeyMaterialB64) {
    const material = b64d(encKeyMaterialB64);
    return crypto.subtle.importKey(
        "raw", 
        material, 
        { name: "AES-GCM" }, 
        false, 
        ["encrypt", "decrypt"]
    );
}

/**
 * Ouvre un vault :
 * - récupère salt/iterations
 * - calcule verifier côté client et le poste à /check
 * - si ok, dérive/importe la clé AES en RAM (currentVault.key)
 * @param {number} vaultId
 * @param {string} password
 * @returns {Promise<{ok:boolean, error?:string}>}
 */
export async function openVault(vaultId, password) {
    const p = await (await fetch(`/api/vaults/${vaultId}/params`)).json();
    const { verifierB64, encKeyMaterialB64 } =
        await computeVerifierFromPassword(password, p.vaultSaltB64, p.iterations);

    const check = await (await fetch(`/api/vaults/${vaultId}/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ verifierB64 }) // pas de password, seulement le dérivé
    })).json();

    if (!check.ok) return { ok: false, error: "Mot de passe maître invalide." };

    const key = await deriveEncKeyFromEncKeyMaterial(encKeyMaterialB64);
    currentVault = { id: vaultId, key };
    return { ok: true };
}

// ==============================
// CHIFFREMENT / DÉCHIFFREMENT DES ENTRÉES
// ==============================

/**
 * Chiffre un champ texte avec la clé du vault.
 * Utilise un IV aléatoire unique et, si fourni, une AAD (liée au contexte).
 * @param {string} text - contenu à chiffrer.
 * @param {string} [aad] - Additional Authenticated Data (ex: "field:password").
 * @returns {Promise<{cipher:Uint8Array, tag:Uint8Array, iv:Uint8Array}>}
 */
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

/**
 * Déchiffre un champ chiffré avec la clé du vault.
 * Échoue si tag invalide, si IV AAD ou ciphertext modifiés.
 * @param {Uint8Array} cipherU8
 * @param {Uint8Array} tagU8
 * @param {Uint8Array} ivU8
 * @param {string} [aad]
 * @returns {Promise<string>} - texte en clair.
 */
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
 * Lit les valeurs depuis le DOM, renvoie des champs encodés en Base64
 * (cipher, tag, iv) pour un POST JSON.
 * @returns {Promise<object>} - payload prêt pour /api/vaults/{id}/entries
 */
export async function encryptEntryForOpenVault() {
    if (!currentVault.key) throw new Error("Vault non ouvert");
    const get = id => document.getElementById(id)?.value ?? "";
    const name = get("name"), pwd = get("pwd"), url = get("url"), notes = get("notes");

    // 💡 AAD minimal par champ (tu peux lier au vaultId si tu veux : `vault:${currentVault.id}|field:xxx`)
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
 * Déchiffre une entrée (reçue chiffrée depuis l’API) en clair côté client.
 * @param {object} record - champs Base64: cipherX/tagX/ivX
 * @returns {Promise<{name:string, password:string, url:string, notes:string}>}
 */
export async function decryptVaultEntry(record) {
    const out = {};
    out.password = await decFieldWithVaultKey(
        b64d(record.cipherPasswordB64), b64d(record.tagPasswordB64), b64d(record.ivPasswordB64), "field:password");
    out.name     = await decFieldWithVaultKey(
        b64d(record.cipherNameB64),     b64d(record.tagNameB64),     b64d(record.ivNameB64),     "field:name");
    out.url      = await decFieldWithVaultKey(
        b64d(record.cipherUrlB64),      b64d(record.tagUrlB64),      b64d(record.ivUrlB64),      "field:url");
    out.notes    = await decFieldWithVaultKey(
        b64d(record.cipherNotesB64),    b64d(record.tagNotesB64),    b64d(record.ivNotesB64),    "field:notes");
    return out;
}

// ==============================
// Rendu DOM côté client
// ==============================

/**
 * Rend la liste des entrées dans #vault-list après déchiffrement côté client.
 * @param {Array<object>} records - tableau d’entrées chiffrées (JSON de l’API)
 */
export async function renderVaultEntries(records) {
    const list = document.getElementById("vault-list");
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