// wwwroot/crypto.js

const textEnc = new TextEncoder();
const textDec = new TextDecoder();

function toB64(a) { return btoa(String.fromCharCode(...new Uint8Array(a))); }
function fromB64(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }

async function deriveKeyPBKDF2(password, saltB64, iterations = 600000) {
    const pwKey = await crypto.subtle.importKey(
        "raw", textEnc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    const salt = fromB64(saltB64);
    return await crypto.subtle.deriveKey(
        { name: "PBKDF2", hash: "SHA-256", salt, iterations },
        pwKey,
        { name: "AES-GCM", length: 256 },
        false, // non-exportable
        ["encrypt", "decrypt"]
    );
}

export async function encryptPBKDF2_GCM(plaintext, password, iterations = 600000) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const key  = await deriveKeyPBKDF2(password, toB64(salt), iterations);
    const ct   = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, textEnc.encode(plaintext));
    // WebCrypto attache le tag dans le ciphertext (GCM mode)
    return {
        ciphertextB64: toB64(ct),
        ivB64: toB64(iv),
        saltB64: toB64(salt),
        iterations
    };
}

export async function decryptPBKDF2_GCM(ciphertextB64, password, ivB64, saltB64, iterations) {
    const key = await deriveKeyPBKDF2(password, saltB64, iterations);
    const pt  = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromB64(ivB64) },
        key,
        fromB64(ciphertextB64)
    );
    return new TextDecoder().decode(pt);
}