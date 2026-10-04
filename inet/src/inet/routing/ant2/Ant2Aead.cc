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

namespace inet {
namespace ant2aead {

bool parseName(const std::string& n, Algorithm& out)
{
    if (n == "ascon128"         || n == "Ascon-AEAD128")      { out = ASCON128;         return true; }
    if (n == "aes128gcm"        || n == "AES-128-GCM")        { out = AES128GCM;        return true; }
    if (n == "aes192gcm"        || n == "AES-192-GCM")        { out = AES192GCM;        return true; }
    if (n == "aes256gcm"        || n == "AES-256-GCM")        { out = AES256GCM;        return true; }
    if (n == "chacha20poly1305" || n == "ChaCha20-Poly1305")  { out = CHACHA20POLY1305; return true; }
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
    }
    return 0;
}

int nonceLen(Algorithm alg)
{
    // Ascon-AEAD128 usa un nonce da 128 bit; GCM e ChaCha20-Poly1305 usano
    // quello "canonico" da 96 bit previsto dai rispettivi standard.
    return (alg == ASCON128) ? 16 : 12;
}

// ---------------------------------------------------------------------------
// Ascon
// ---------------------------------------------------------------------------
static bool asconEncrypt(const uint8_t *key, const uint8_t *nonce,
                         const uint8_t *aad, size_t aadLen,
                         const uint8_t *pt, size_t ptLen,
                         uint8_t *ct, uint8_t *tag)
{
    // L'implementazione di riferimento restituisce ciphertext||tag in un unico
    // buffer: qui lo separiamo per uniformarci all'interfaccia comune.
    std::vector<uint8_t> combined(ptLen + TAG_LEN);
    unsigned long long clen = 0;
    if (crypto_aead_encrypt(combined.data(), &clen, pt, ptLen,
                            aad, aadLen, nullptr, nonce, key) != 0)
        return false;
    if (clen != ptLen + TAG_LEN)
        return false;
    memcpy(ct, combined.data(), ptLen);
    memcpy(tag, combined.data() + ptLen, TAG_LEN);
    return true;
}

static bool asconDecrypt(const uint8_t *key, const uint8_t *nonce,
                         const uint8_t *aad, size_t aadLen,
                         const uint8_t *ct, size_t ctLen,
                         const uint8_t *tag, uint8_t *pt)
{
    std::vector<uint8_t> combined(ctLen + TAG_LEN);
    memcpy(combined.data(), ct, ctLen);
    memcpy(combined.data() + ctLen, tag, TAG_LEN);
    unsigned long long mlen = 0;
    if (crypto_aead_decrypt(pt, &mlen, nullptr, combined.data(), combined.size(),
                            aad, aadLen, nonce, key) != 0)
        return false;
    return mlen == ctLen;
}

// ---------------------------------------------------------------------------
// AES-GCM (template sulla variante di AES) e ChaCha20-Poly1305
// ---------------------------------------------------------------------------
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
    c.computeTag(tag, TAG_LEN);
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
    if (!c.checkTag(tag, TAG_LEN)) {
        memset(pt, 0, ctLen);   // non lasciare in giro plaintext non autenticato
        return false;
    }
    return true;
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
    }
    return false;
}

} // namespace ant2aead
} // namespace inet
