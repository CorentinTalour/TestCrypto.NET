// --- UTILITAIRES DE BASE ENCODAGE / DÉCODAGE ---

// Encodage texte → Uint8Array
const enc = new TextEncoder();

// Conversion d’un tableau d’octets vers Base64 (pour stockage en BDD)
const b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));

// Conversion d’une chaîne Base64 vers Uint8Array (pour déchiffrement)
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));


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
    // Génère un IV aléatoire de 12 octets (taille recommandée pour GCM)
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Chiffre le texte clair avec AES-GCM
    // -> additionalData (AAD) permet d’associer des métadonnées (ex : “field:name”)
    const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: aad ? enc.encode(aad) : undefined },
        key,
        enc.encode(text ?? "")
    );

    // Retourne le ciphertext et l’IV en Base64
    return { cipherB64: b64(ct), ivB64: b64(iv) };
}


// --- CHIFFREMENT DE TOUS LES CHAMPS DE L’ENTRÉE ---

// Fonction principale appelée depuis Blazor
// → Chiffre name, password, url, notes avec un IV unique pour chaque champ
// → Renvoie un objet prêt à être envoyé à l’API
export async function encryptEntrySeparateFields(password) {

    // Récupère les valeurs directement dans le DOM
    const get = id => document.getElementById(id)?.value ?? "";
    const name = get("name"), pwd = get("pwd"), url = get("url"), notes = get("notes");

    // Génére un sel aléatoire (16 octets)
    const salt = crypto.getRandomValues(new Uint8Array(16));

    // Dérive la clé à partir du mot de passe maître + sel
    const key = await deriveKeyPBKDF2(password, b64(salt), 600000);

    // Chiffre chaque champ avec un IV différent et un AAD descriptif
    const p  = await encField(key, pwd,   "field:password");
    const n  = await encField(key, name,  "field:name");
    const u  = await encField(key, url,   "field:url");
    const no = await encField(key, notes, "field:notes");

    // Retourne l’ensemble des données chiffrées + paramètres de dérivation
    return {
        cipherPasswordB64: p.cipherB64, ivPasswordB64: p.ivB64,
        cipherNameB64:     n.cipherB64, ivNameB64:     n.ivB64,
        cipherUrlB64:      u.cipherB64, ivUrlB64:      u.ivB64,
        cipherNotesB64:    no.cipherB64,ivNotesB64:    no.ivB64,
        saltB64: b64(salt),
        iterations: 600000
    };
}


// --- DÉCHIFFREMENT DES CHAMPS ---

// Prend une entrée chiffrée depuis la BDD et le mot de passe maître
// → Re-dérive la même clé AES
// → Déchiffre chaque champ séparément (en utilisant ses IV et AAD)
export async function decryptEntrySeparateFields(record, password) {

    // Re-dérive la clé AES à partir du mot de passe maître et du sel stocké
    const key = await deriveKeyPBKDF2(password, record.saltB64, record.iterations);

    // Fonction interne de déchiffrement d’un champ
    const dec = async (cipherB64, ivB64, aad) => {
        const pt = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: b64d(ivB64), additionalData: aad ? enc.encode(aad) : undefined },
            key,
            b64d(cipherB64)
        );
        return new TextDecoder().decode(pt);
    };

    // Retourne les 4 champs déchiffrés (en clair, côté client uniquement)
    return {
        password: await dec(record.cipherPasswordB64, record.ivPasswordB64, "field:password"),
        name:     await dec(record.cipherNameB64,     record.ivNameB64,     "field:name"),
        url:      await dec(record.cipherUrlB64,      record.ivUrlB64,      "field:url"),
        notes:    await dec(record.cipherNotesB64,    record.ivNotesB64,    "field:notes"),
    };
}


// --- DEBUG (facultatif) ---
console.log("[crypto.js] exports:", { encryptEntrySeparateFields, decryptEntrySeparateFields });