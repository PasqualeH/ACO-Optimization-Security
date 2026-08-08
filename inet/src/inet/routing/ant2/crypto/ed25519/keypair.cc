// Rinominato da .c a .cc e avvolto in extern "C" per essere compilato
// insieme al resto del progetto C++ senza problemi di name-mangling
// (il sistema di build di OMNeT++ non riconosce i file .c come sorgenti).
#ifdef __cplusplus
extern "C" {
#endif
#include "ed25519.h"
#include "sha512.h"
#include "ge.h"


void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) {
    ge_p3 A;

    sha512(seed, 32, private_key);
    private_key[0] &= 248;
    private_key[31] &= 63;
    private_key[31] |= 64;

    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);
}
#ifdef __cplusplus
}
#endif
