// Ant2Sign.cc
#include "inet/routing/ant2/Ant2Sign.h"

#include <cstring>
#include <cstdio>

extern "C" {
    #include "inet/routing/ant2/crypto/ed25519/ed25519.h"
    #include "inet/routing/ant2/crypto/ecdsa/uECC.h"
}

#include "inet/routing/ant2/crypto/aead/SHA256.h"

namespace inet {
namespace ant2sign {

// ---------------------------------------------------------------------------
// Generatore di numeri casuali per micro-ecc.
//
// ECDSA ha bisogno di un valore casuale fresco a ogni firma. micro-ecc non ne
// ha uno proprio: va fornito dall'applicazione. Qui si usa la stessa sorgente
// gia' impiegata dal progetto per i semi Ed25519, cioe' /dev/urandom
// (incapsulato in ed25519_create_seed).
// ---------------------------------------------------------------------------
static int rngPerMicroEcc(uint8_t *dest, unsigned size)
{
    while (size > 0) {
        unsigned char blocco[32];
        if (ed25519_create_seed(blocco) != 0)
            return 0;                      // 0 = fallimento, per micro-ecc
        unsigned n = (size < 32) ? size : 32;
        memcpy(dest, blocco, n);
        dest += n;
        size -= n;
    }
    return 1;
}

static const struct uECC_Curve_t *curvaP256()
{
    static bool rngImpostato = false;
    if (!rngImpostato) {
        uECC_set_rng(&rngPerMicroEcc);
        rngImpostato = true;
    }
    return uECC_secp256r1();
}

// ECDSA firma un digest, non il messaggio. Per la curva P-256 lo standard
// prevede SHA-256, che produce esattamente i 32 byte attesi dalla curva.
static void sha256(const uint8_t *msg, size_t len, uint8_t *out32)
{
    SHA256 h;
    h.reset();
    h.update(msg, len);
    h.finalize(out32, 32);
}

// ---------------------------------------------------------------------------

bool parseName(const std::string& n, Algorithm& out)
{
    if (n == "ed25519"    || n == "Ed25519")      { out = ED25519;    return true; }
    if (n == "ecdsap256"  || n == "ecdsa-p256" ||
        n == "ECDSA-P256" || n == "secp256r1")    { out = ECDSA_P256; return true; }
    return false;
}

const char *name(Algorithm alg)
{
    switch (alg) {
        case ED25519:    return "Ed25519";
        case ECDSA_P256: return "ECDSA-P256 (SHA-256)";
    }
    return "sconosciuto";
}

int pubKeyLen(Algorithm alg)  { return (alg == ED25519) ? 32 : 64; }
int privKeyLen(Algorithm alg) { return (alg == ED25519) ? 64 : 32; }

bool generateKeypair(Algorithm alg, const uint8_t *seed32,
                     uint8_t *outPub, uint8_t *outPriv)
{
    if (alg == ED25519) {
        ed25519_create_keypair(outPub, outPriv, seed32);
        return true;
    }
    // micro-ecc genera la coppia usando il proprio RNG; il seme non entra
    // direttamente, ma la sorgente di casualita' e' la stessa.
    (void)seed32;
    return uECC_make_key(outPub, outPriv, curvaP256()) == 1;
}

bool sign(Algorithm alg, const uint8_t *priv, const uint8_t *pub,
          const uint8_t *msg, size_t len, uint8_t *outSig)
{
    if (alg == ED25519) {
        ed25519_sign(outSig, msg, len, pub, priv);
        return true;
    }
    uint8_t digest[32];
    sha256(msg, len, digest);
    return uECC_sign(priv, digest, sizeof(digest), outSig, curvaP256()) == 1;
}

bool verify(Algorithm alg, const uint8_t *pub,
            const uint8_t *msg, size_t len, const uint8_t *sig)
{
    if (alg == ED25519)
        return ed25519_verify(sig, msg, len, pub) != 0;

    uint8_t digest[32];
    sha256(msg, len, digest);
    return uECC_verify(pub, digest, sizeof(digest), sig, curvaP256()) == 1;
}

} // namespace ant2sign
} // namespace inet
