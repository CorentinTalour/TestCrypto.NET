// --- UTILITAIRES DE BASE ENCODAGE / DÉCODAGE ---

// Encodage texte → Uint8Array
const enc = new TextEncoder();

// Conversion d’un tableau d’octets vers Base64 (pour stockage en BDD)
const b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));

// Conversion d’une chaîne Base64 vers Uint8Array (pour déchiffrement)
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

// Taille tag AES-GCM (octets). 128 bits par défaut.
const TAG_BYTES = 16;

// Split [cipher||tag] -> {cipher, tag}
function splitCtAndTag(buf) {
    const u = new Uint8Array(buf);
    const cipher = u.slice(0, u.length - TAG_BYTES);
    const tag = u.slice(u.length - TAG_BYTES);
    return { cipher, tag };
}

// Join cipher + tag -> ArrayBuffer
function joinCtAndTag(cipherU8, tagU8) {
    const out = new Uint8Array(cipherU8.length + tagU8.length);
    out.set(cipherU8, 0);
    out.set(tagU8, cipherU8.length);
    return out.buffer;
}


// --- FONCTION DE DÉRIVATION DE CLÉ (PBKDF2) ---

// Dérive une clé symétrique AES-256 à partir d’un mot de passe maître
// - password : mot de passe maître saisi par l’utilisateur
// - saltB64  : sel (aléatoire, stocké avec le secret, en Base64)
// - iterations : nombre d’itérations PBKDF2 (ex : 600 000)
async function deriveKeyPBKDF2(password, saltB64, iterations) {
    // Importe le mot de passe maître en tant que clé de base PBKDF2
    const pwKey = await crypto.subtle.importKey(
        "raw",                     // clé brute (non formatée)
        enc.encode(password),       // convertit le mot de passe en bytes
        { name: "PBKDF2" },         // algorithme de dérivation
        false,                      // clé non exportable
        ["deriveKey"]               // utilisable pour dériver une autre clé
    );

    // Dérive une clé AES-GCM 256 bits à partir du mot de passe + sel
    return await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            hash: "SHA-256",         // fonction de hachage interne
            salt: b64d(saltB64),     // le sel (converti depuis Base64)
            iterations               // renforce le coût du calcul
        },
        pwKey,                       // clé de base (mot de passe)
        { name: "AES-GCM", length: 256 }, // clé cible : AES 256 bits
        false,                       // non exportable
        ["encrypt", "decrypt"]       // utilisable pour chiffrer/déchiffrer
    );
}


// --- CHIFFREMENT D’UN CHAMP (AVEC SON PROPRES IV + AAD) ---

// Chiffre un champ texte donné avec la clé dérivée
// - key : clé AES dérivée (256 bits)
// - text : texte à chiffrer
// - aad : (facultatif) "Associated Authenticated Data" — ici le type du champ
async function encField(key, text, aad) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ctFull = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: aad ? enc.encode(aad) : undefined },
        key,
        enc.encode(text ?? "")
    );

    const { cipher, tag } = splitCtAndTag(ctFull);
    return { cipherB64: b64(cipher), tagB64: b64(tag), ivB64: b64(iv) };
}

// --- CHIFFREMENT DE TOUS LES CHAMPS DE L’ENTRÉE ---

// Fonction principale appelée depuis Blazor
// → Chiffre name, password, url, notes avec un IV unique pour chaque champ
// → Renvoie un objet prêt à être envoyé à l’API
export async function encryptEntrySeparateFields(password) {
    const get = id => document.getElementById(id)?.value ?? "";
    const name = get("name"), pwd = get("pwd"), url = get("url"), notes = get("notes");
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKeyPBKDF2(password, b64(salt), 600000);

    const p  = await encField(key, pwd,   "field:password");
    const n  = await encField(key, name,  "field:name");
    const u  = await encField(key, url,   "field:url");
    const no = await encField(key, notes, "field:notes");

    return {
        cipherPasswordB64: p.cipherB64, tagPasswordB64: p.tagB64, ivPasswordB64: p.ivB64,
        cipherNameB64:     n.cipherB64, tagNameB64:     n.tagB64, ivNameB64:     n.ivB64,
        cipherUrlB64:      u.cipherB64, tagUrlB64:      u.tagB64, ivUrlB64:      u.ivB64,
        cipherNotesB64:    no.cipherB64,tagNotesB64:    no.tagB64,ivNotesB64:    no.ivB64,
        saltB64: b64(salt),
        iterations: 600000
    };
}


// --- DÉCHIFFREMENT DES CHAMPS ---

// Prend une entrée chiffrée depuis la BDD et le mot de passe maître
// → Re-dérive la même clé AES
// → Déchiffre chaque champ séparément (en utilisant ses IV et AAD)
export async function decryptEntrySeparateFields(record, password) {
    const key = await deriveKeyPBKDF2(password, record.saltB64, record.iterations);

    const dec = async (cipherB64, tagB64, ivB64, aad) => {
        const cipherU8 = b64d(cipherB64);
        const tagU8 = b64d(tagB64);
        const ctFull = joinCtAndTag(cipherU8, tagU8);
        const pt = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: b64d(ivB64), additionalData: aad ? enc.encode(aad) : undefined },
            key,
            ctFull
        );
        return new TextDecoder().decode(pt);
    };

    return {
        password: await dec(record.cipherPasswordB64, record.tagPasswordB64, record.ivPasswordB64, "field:password"),
        name:     await dec(record.cipherNameB64,     record.tagNameB64,     record.ivNameB64,     "field:name"),
        url:      await dec(record.cipherUrlB64,      record.tagUrlB64,      record.ivUrlB64,      "field:url"),
        notes:    await dec(record.cipherNotesB64,    record.tagNotesB64,    record.ivNotesB64,    "field:notes"),
    };
}


// --- DEBUG (facultatif) ---
console.log("[crypto.js] exports:", { encryptEntrySeparateFields, decryptEntrySeparateFields });
















// createVaultVerifier(password, iterations = 600000)
// - génère vaultSalt (16 o), dérive 64 octets via PBKDF2
// - split : verifyPart = first 32 o ; encKeyMaterial = last 32 o
// - verifier = SHA-256(verifyPart) -> stocker côté serveur en Base64
// - retourne { vaultSaltB64, iterations, verifierB64, encKeyMaterialB64 }
//   Note: encKeyMaterialB64 n'est pas à stocker dans la BDD. C'est utile en RAM côté client.
export async function createVaultVerifier(password, iterations = 600000) {
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    const b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));
    const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

    // 1) génère un salt pour le vault
    const vaultSalt = crypto.getRandomValues(new Uint8Array(16));
    const vaultSaltB64 = b64(vaultSalt);

    // 2) importe le mot de passe comme clé PBKDF2
    const pwKey = await crypto.subtle.importKey(
        "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
    );

    // 3) dérive 64 octets (512 bits)
    const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt: vaultSalt, iterations },
        pwKey,
        512
    );
    const b = new Uint8Array(bits);

    // 4) split : verifierPart (32 o) + encKeyMaterial (32 o)
    const verifyPart = b.slice(0, 32);
    const encKeyMaterial = b.slice(32, 64);

    // 5) verifier = SHA-256(verifyPart)
    const verifierHash = await crypto.subtle.digest("SHA-256", verifyPart);
    const verifierB64 = b64(verifierHash);

    // 6) encKeyMaterial pour usage en RAM (ex: dériver clé AES ou importer raw key)
    const encKeyMaterialB64 = b64(encKeyMaterial);

    return {
        vaultSaltB64,
        iterations,
        verifierB64,
        encKeyMaterialB64 // garder en mémoire, NE PAS stocker en DB
    };
}

// Helper pour dériver la clé de chiffrement (à garder côté client)
// deriveEncKeyFromEncKeyMaterial(encKeyMaterialB64)
// convertit la matière première encKeyMaterial en clé AES utilisable (non exportable)
export async function deriveEncKeyFromEncKeyMaterial(encKeyMaterialB64) {
    const enc = new TextEncoder();
    const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
    const material = b64d(encKeyMaterialB64);
    // import as raw key material and mark as non-exportable AES-GCM key
    return crypto.subtle.importKey("raw", material, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

// Calcule un verifier à partir d'un password + salt/iterations existants (pour "ouvrir" le vault)
export async function computeVerifierFromPassword(password, vaultSaltB64, iterations = 600000) {
    const enc = new TextEncoder();
    const b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));
    const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

    const pwKey = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt: b64d(vaultSaltB64), iterations },
        pwKey,
        512
    );
    const b = new Uint8Array(bits);
    const verifyPart = b.slice(0, 32);
    const encKeyMaterial = b.slice(32, 64); // utile ensuite pour la clé de chiffrement en RAM
    const verifierHash = await crypto.subtle.digest("SHA-256", verifyPart);
    return {
        verifierB64: b64(verifierHash),
        encKeyMaterialB64: b64(encKeyMaterial)
    };
}














// --- état courant du coffre ouvert (clé AES en RAM) ---
let currentVault = {
    id: null,
    key: null // CryptoKey AES-GCM non exportable
};

// Ouvrir un coffre : vérifie le password et importe la clé AES utilisée pour TOUTES les entrées
export async function openVault(vaultId, password) {
    // 1) params
    const p = await (await fetch(`/api/vaults/${vaultId}/params`)).json(); // { vaultSaltB64, iterations }

    // 2) dérive verifier + encKeyMaterialB64
    const { verifierB64, encKeyMaterialB64 } =
        await computeVerifierFromPassword(password, p.vaultSaltB64, p.iterations);

    // 3) check serveur
    const check = await (await fetch(`/api/vaults/${vaultId}/check`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ verifierB64 })
    })).json();
    if (!check.ok) return { ok: false, error: "Mot de passe maître invalide." };

    // 4) importe la clé AES utilisable (non exportable), en RAM seulement
    const key = await deriveEncKeyFromEncKeyMaterial(encKeyMaterialB64);
    currentVault = { id: vaultId, key };
    return { ok: true };
}

// utilitaire : chiffre un champ avec la clé du coffre
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

// utilitaire : déchiffre un champ avec la clé du coffre (inputs en Uint8Array)
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

// Chiffrer une nouvelle entrée pour le coffre ouvert (renvoie Base64 pour JSON)
export async function encryptEntryForOpenVault() {
    if (!currentVault.key) throw new Error("Vault non ouvert");
    const get = id => document.getElementById(id)?.value ?? "";
    const name = get("name"), pwd = get("pwd"), url = get("url"), notes = get("notes");

    const p  = await encFieldWithVaultKey(pwd,   "field:password");
    const n  = await encFieldWithVaultKey(name,  "field:name");
    const u  = await encFieldWithVaultKey(url,   "field:url");
    const no = await encFieldWithVaultKey(notes, "field:notes");

    // transport en Base64 (JSON friendly)
    return {
        cipherPasswordB64: b64(p.cipher), tagPasswordB64: b64(p.tag), ivPasswordB64: b64(p.iv),
        cipherNameB64:     b64(n.cipher), tagNameB64:     b64(n.tag), ivNameB64:     b64(n.iv),
        cipherUrlB64:      b64(u.cipher), tagUrlB64:      b64(u.tag), ivUrlB64:      b64(u.iv),
        cipherNotesB64:    b64(no.cipher),tagNotesB64:    b64(no.tag),ivNotesB64:    b64(no.iv)
        // NOTE: pas de salt/iterations par entrée
    };
}

// Déchiffrer une entrée du coffre (record JSON Base64 -> objet clair)
export async function decryptVaultEntry(record) {
    const out = {};
    out.password = await decFieldWithVaultKey(b64d(record.cipherPasswordB64), b64d(record.tagPasswordB64), b64d(record.ivPasswordB64), "field:password");
    out.name     = await decFieldWithVaultKey(b64d(record.cipherNameB64),     b64d(record.tagNameB64),     b64d(record.ivNameB64),     "field:name");
    out.url      = await decFieldWithVaultKey(b64d(record.cipherUrlB64),      b64d(record.tagUrlB64),      b64d(record.ivUrlB64),      "field:url");
    out.notes    = await decFieldWithVaultKey(b64d(record.cipherNotesB64),    b64d(record.tagNotesB64),    b64d(record.ivNotesB64),    "field:notes");
    return out;
}