// Ant2Aead.cc
#include "inet/routing/ant2/Ant2Aead.h"

#include <cstring>
#include <vector>

extern "C" {
    #include "inet/routing/ant2/crypto/ascon/crypto_aead.h"
}

// Le intestazioni della libreria AES/ChaCha vivono nel namespace globale.
// Sono incluse SOLO qui dentro, cosi' il resto del progetto non le vede mai
// e il rischio di collisioni di nomi resta confinato a questo file.
#include "inet/routing/ant2/crypto/aead/AES.h"
#include "inet/routing/ant2/crypto/aead/GCM.h"
#include "inet/routing/ant2/crypto/aead/ChaChaPoly.h"

// Finalisti NIST Lightweight Cryptography (libreria lwc-finalists, MIT).
// Le intestazioni dichiarano gia' le funzioni in extern "C".
#include "inet/routing/ant2/crypto/xoodyak/xoodyak-aead.h"
#include "inet/routing/ant2/crypto/tinyjambu/tinyjambu-aead.h"

namespace inet {
namespace ant2aead {

bool parseName(const std::string& n, Algorithm& out)
{
    if (n == "ascon128"         || n == "Ascon-AEAD128")      { out = ASCON128;         return true; }
    if (n == "aes128gcm"        || n == "AES-128-GCM")        { out = AES128GCM;        return true; }
    if (n == "aes192gcm"        || n == "AES-192-GCM")        { out = AES192GCM;        return true; }
    if (n == "aes256gcm"        || n == "AES-256-GCM")        { out = AES256GCM;        return true; }
    if (n == "chacha20poly1305" || n == "ChaCha20-Poly1305")  { out = CHACHA20POLY1305; return true; }
    if (n == "xoodyak"          || n == "Xoodyak")            { out = XOODYAK;          return true; }
    if (n == "tinyjambu128"     || n == "TinyJAMBU-128")      { out = TINYJAMBU128;     return true; }
    return false;
}

const char *name(Algorithm alg)
{
    switch (alg) {
        case ASCON128:         return "Ascon-AEAD128";
        case AES128GCM:        return "AES-128-GCM";
        case AES192GCM:        return "AES-192-GCM";
        case AES256GCM:        return "AES-256-GCM";
        case CHACHA20POLY1305: return "ChaCha20-Poly1305";
        case XOODYAK:          return "Xoodyak";
        case TINYJAMBU128:     return "TinyJAMBU-128";
    }
    return "sconosciuto";
}

int keyLen(Algorithm alg)
{
    switch (alg) {
        case ASCON128:         return 16;
        case AES128GCM:        return 16;
        case AES192GCM:        return 24;
        case AES256GCM:        return 32;
        case CHACHA20POLY1305: return 32;
        // Entrambi i finalisti LWC usano una chiave da 128 bit: ricevono gli
        // stessi 16 byte di chiave di gruppo che riceve Ascon.
        case XOODYAK:          return 16;
        case TINYJAMBU128:     return 16;
    }
    return 0;
}

int nonceLen(Algorithm alg)
{
    // Ascon-AEAD128 e Xoodyak usano un nonce da 128 bit; GCM,
    // ChaCha20-Poly1305 e TinyJAMBU-128 quello da 96 bit previsto dai
    // rispettivi standard/specifiche.
    switch (alg) {
        case ASCON128:
        case XOODYAK:          return 16;
        case AES128GCM:
        case AES192GCM:
        case AES256GCM:
        case CHACHA20POLY1305:
        case TINYJAMBU128:     return 12;
    }
    return 0;
}

int tagLen(Algorithm alg)
{
    // TinyJAMBU-128 e' l'unico con tag da 64 bit (scelta dei progettisti per
    // ridurre l'overhead sui messaggi brevi; la sicurezza contro la
    // falsificazione e' quindi di 64 bit invece di 128). Tutti gli altri: 128 bit.
    return (alg == TINYJAMBU128) ? 8 : 16;
}

// ---------------------------------------------------------------------------
// Ascon
// ---------------------------------------------------------------------------
static const size_t ASCON_TAG = 16;     // CRYPTO_ABYTES di Ascon-AEAD128

static bool asconEncrypt(const uint8_t *key, const uint8_t *nonce,
                         const uint8_t *aad, size_t aadLen,
                         const uint8_t *pt, size_t ptLen,
                         uint8_t *ct, uint8_t *tag)
{
    // L'implementazione di riferimento restituisce ciphertext||tag in un unico
    // buffer: qui lo separiamo per uniformarci all'interfaccia comune.
    std::vector<uint8_t> combined(ptLen + ASCON_TAG);
    unsigned long long clen = 0;
    if (crypto_aead_encrypt(combined.data(), &clen, pt, ptLen,
                            aad, aadLen, nullptr, nonce, key) != 0)
        return false;
    if (clen != ptLen + ASCON_TAG)
        return false;
    memcpy(ct, combined.data(), ptLen);
    memcpy(tag, combined.data() + ptLen, ASCON_TAG);
    return true;
}

static bool asconDecrypt(const uint8_t *key, const uint8_t *nonce,
                         const uint8_t *aad, size_t aadLen,
                         const uint8_t *ct, size_t ctLen,
                         const uint8_t *tag, uint8_t *pt)
{
    std::vector<uint8_t> combined(ctLen + ASCON_TAG);
    memcpy(combined.data(), ct, ctLen);
    memcpy(combined.data() + ctLen, tag, ASCON_TAG);
    unsigned long long mlen = 0;
    if (crypto_aead_decrypt(pt, &mlen, nullptr, combined.data(), combined.size(),
                            aad, aadLen, nonce, key) != 0)
        return false;
    return mlen == ctLen;
}

// ---------------------------------------------------------------------------
// AES-GCM (template sulla variante di AES) e ChaCha20-Poly1305
// ---------------------------------------------------------------------------
static const size_t GCM_TAG = 16;       // tag "pieno" da 128 bit di GCM e Poly1305

template <typename CIPHER>
static bool gcmEncrypt(size_t klen, const uint8_t *key, const uint8_t *nonce,
                       const uint8_t *aad, size_t aadLen,
                       const uint8_t *pt, size_t ptLen,
                       uint8_t *ct, uint8_t *tag)
{
    CIPHER c;
    if (!c.setKey(key, klen)) return false;
    if (!c.setIV(nonce, 12))  return false;
    c.addAuthData(aad, aadLen);
    c.encrypt(ct, pt, ptLen);
    c.computeTag(tag, GCM_TAG);
    return true;
}

template <typename CIPHER>
static bool gcmDecrypt(size_t klen, const uint8_t *key, const uint8_t *nonce,
                       const uint8_t *aad, size_t aadLen,
                       const uint8_t *ct, size_t ctLen,
                       const uint8_t *tag, uint8_t *pt)
{
    CIPHER c;
    if (!c.setKey(key, klen)) return false;
    if (!c.setIV(nonce, 12))  return false;
    c.addAuthData(aad, aadLen);
    c.decrypt(pt, ct, ctLen);
    // checkTag() fa un confronto a tempo costante e va chiamato UNA volta sola:
    // e' la funzione che finalizza lo stato interno.
    if (!c.checkTag(tag, GCM_TAG)) {
        memset(pt, 0, ctLen);   // non lasciare in giro plaintext non autenticato
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Xoodyak e TinyJAMBU-128 (finalisti NIST LWC, libreria lwc-finalists)
// ---------------------------------------------------------------------------
// Le due funzioni della libreria hanno la stessa forma dell'API NIST: in
// cifratura producono un unico buffer ciphertext||tag, in decifratura lo
// vogliono di nuovo unito. Un solo modello (template) le adatta entrambe
// all'interfaccia comune, separando/riunendo il tag di TAGLEN byte.
typedef int (*LwcEncryptFn)(unsigned char *, size_t *,
                            const unsigned char *, size_t,
                            const unsigned char *, size_t,
                            const unsigned char *, const unsigned char *);
typedef int (*LwcDecryptFn)(unsigned char *, size_t *,
                            const unsigned char *, size_t,
                            const unsigned char *, size_t,
                            const unsigned char *, const unsigned char *);

template <LwcEncryptFn ENC, size_t TAGLEN>
static bool lwcEncrypt(const uint8_t *key, const uint8_t *nonce,
                       const uint8_t *aad, size_t aadLen,
                       const uint8_t *pt, size_t ptLen,
                       uint8_t *ct, uint8_t *tag)
{
    std::vector<uint8_t> combined(ptLen + TAGLEN);
    size_t clen = 0;
    if (ENC(combined.data(), &clen, pt, ptLen, aad, aadLen, nonce, key) != 0)
        return false;
    if (clen != ptLen + TAGLEN)
        return false;
    memcpy(ct, combined.data(), ptLen);
    memcpy(tag, combined.data() + ptLen, TAGLEN);
    return true;
}

template <LwcDecryptFn DEC, size_t TAGLEN>
static bool lwcDecrypt(const uint8_t *key, const uint8_t *nonce,
                       const uint8_t *aad, size_t aadLen,
                       const uint8_t *ct, size_t ctLen,
                       const uint8_t *tag, uint8_t *pt)
{
    std::vector<uint8_t> combined(ctLen + TAGLEN);
    memcpy(combined.data(), ct, ctLen);
    memcpy(combined.data() + ctLen, tag, TAGLEN);
    size_t mlen = 0;
    // La libreria confronta il tag a tempo costante e, se e' sbagliato,
    // azzera da sola il plaintext prodotto (aead_check_tag).
    if (DEC(pt, &mlen, combined.data(), combined.size(), aad, aadLen, nonce, key) != 0)
        return false;
    return mlen == ctLen;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------
bool encrypt(Algorithm alg,
             const uint8_t *key, const uint8_t *nonce,
             const uint8_t *aad, size_t aadLen,
             const uint8_t *pt, size_t ptLen,
             uint8_t *ct, uint8_t *tag)
{
    switch (alg) {
        case ASCON128:  return asconEncrypt(key, nonce, aad, aadLen, pt, ptLen, ct, tag);
        case AES128GCM: return gcmEncrypt<GCM<AES128>>(16, key, nonce, aad, aadLen, pt, ptLen, ct, tag);
        case AES192GCM: return gcmEncrypt<GCM<AES192>>(24, key, nonce, aad, aadLen, pt, ptLen, ct, tag);
        case AES256GCM: return gcmEncrypt<GCM<AES256>>(32, key, nonce, aad, aadLen, pt, ptLen, ct, tag);
        case CHACHA20POLY1305:
                        return gcmEncrypt<ChaChaPoly>(32, key, nonce, aad, aadLen, pt, ptLen, ct, tag);
        case XOODYAK:   return lwcEncrypt<xoodyak_aead_encrypt, XOODYAK_TAG_SIZE>(
                               key, nonce, aad, aadLen, pt, ptLen, ct, tag);
        case TINYJAMBU128:
                        return lwcEncrypt<tiny_jambu_128_aead_encrypt, TINY_JAMBU_TAG_SIZE>(
                               key, nonce, aad, aadLen, pt, ptLen, ct, tag);
    }
    return false;
}

bool decrypt(Algorithm alg,
             const uint8_t *key, const uint8_t *nonce,
             const uint8_t *aad, size_t aadLen,
             const uint8_t *ct, size_t ctLen,
             const uint8_t *tag,
             uint8_t *pt)
{
    switch (alg) {
        case ASCON128:  return asconDecrypt(key, nonce, aad, aadLen, ct, ctLen, tag, pt);
        case AES128GCM: return gcmDecrypt<GCM<AES128>>(16, key, nonce, aad, aadLen, ct, ctLen, tag, pt);
        case AES192GCM: return gcmDecrypt<GCM<AES192>>(24, key, nonce, aad, aadLen, ct, ctLen, tag, pt);
        case AES256GCM: return gcmDecrypt<GCM<AES256>>(32, key, nonce, aad, aadLen, ct, ctLen, tag, pt);
        case CHACHA20POLY1305:
                        return gcmDecrypt<ChaChaPoly>(32, key, nonce, aad, aadLen, ct, ctLen, tag, pt);
        case XOODYAK:   return lwcDecrypt<xoodyak_aead_decrypt, XOODYAK_TAG_SIZE>(
                               key, nonce, aad, aadLen, ct, ctLen, tag, pt);
        case TINYJAMBU128:
                        return lwcDecrypt<tiny_jambu_128_aead_decrypt, TINY_JAMBU_TAG_SIZE>(
                               key, nonce, aad, aadLen, ct, ctLen, tag, pt);
    }
    return false;
}

// Controlli a tempo di compilazione: se un giorno la libreria cambiasse le
// dimensioni, la build si fermerebbe qui invece di produrre messaggi sbagliati.
static_assert(XOODYAK_KEY_SIZE == 16 && XOODYAK_NONCE_SIZE == 16 && XOODYAK_TAG_SIZE == 16,
              "Xoodyak: dimensioni inattese");
static_assert(TINY_JAMBU_128_KEY_SIZE == 16 && TINY_JAMBU_NONCE_SIZE == 12 && TINY_JAMBU_TAG_SIZE == 8,
              "TinyJAMBU-128: dimensioni inattese");
static_assert(XOODYAK_TAG_SIZE <= MAX_TAG_LEN && TINY_JAMBU_TAG_SIZE <= MAX_TAG_LEN,
              "MAX_TAG_LEN troppo piccolo");

} // namespace ant2aead
} // namespace inet
