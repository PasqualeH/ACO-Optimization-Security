// Ant2Sign.h
//
// Strato di adattamento che espone UNA SOLA interfaccia per i due algoritmi di
// firma digitale messi a confronto nella tesi:
//
//   - Ed25519      (RFC 8032)  chiave pubblica 32 B, privata 64 B, firma 64 B
//   - ECDSA P-256  (FIPS 186-4, curva secp256r1, con SHA-256)
//                              chiave pubblica 64 B, privata 32 B, firma 64 B
//
// LA FIRMA E' DI 64 BYTE IN ENTRAMBI I CASI. Come per gli AEAD, questo
// significa che il formato dei messaggi non cambia al variare dell'algoritmo:
// le differenze osservate riguardano solo il costo computazionale.
//
// DUE DIFFERENZE QUALITATIVE DA RICORDARE, oltre ai tempi:
//
//  1) Ed25519 e' DETERMINISTICO: la firma dipende solo da chiave e messaggio.
//     ECDSA richiede invece un valore casuale k diverso per ogni firma, e se
//     due firme riusano lo stesso k la chiave privata si ricava con un calcolo
//     elementare. E' un requisito operativo in piu' che ricade sul generatore
//     di numeri casuali del drone.
//  2) Ed25519 non richiede di scegliere una funzione di hash: la usa
//     internamente (SHA-512). Con ECDSA l'hash va scelto e dichiarato; qui si
//     usa SHA-256, come previsto dalle suite standard per la curva P-256.
//
// Implementazioni: crypto/ed25519 (orlp/ed25519, gia' presente) e
// crypto/ecdsa (micro-ecc di Ken MacKay, licenza BSD 2-clause).

#ifndef __INET_ANT2SIGN_H
#define __INET_ANT2SIGN_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace inet {
namespace ant2sign {

enum Algorithm {
    ED25519 = 0,
    ECDSA_P256
};

static const int MAX_PUBKEY_LEN  = 64;
static const int MAX_PRIVKEY_LEN = 64;
static const int SIG_LEN         = 64;   // uguale per entrambi

bool parseName(const std::string& name, Algorithm& out);
const char *name(Algorithm alg);
int pubKeyLen(Algorithm alg);
int privKeyLen(Algorithm alg);

// Genera una coppia di chiavi. 'seed' e' un array di 32 byte casuali; per
// Ed25519 e' il seme da cui la coppia deriva in modo deterministico, per ECDSA
// viene usato per inizializzare il generatore interno.
bool generateKeypair(Algorithm alg, const uint8_t *seed32,
                     uint8_t *outPub, uint8_t *outPriv);

// Firma 'len' byte. 'pub' serve solo a Ed25519 (l'implementazione di
// riferimento lo richiede per non doverlo ricalcolare a ogni firma); per ECDSA
// puo' essere nullptr.
bool sign(Algorithm alg, const uint8_t *priv, const uint8_t *pub,
          const uint8_t *msg, size_t len, uint8_t *outSig);

bool verify(Algorithm alg, const uint8_t *pub,
            const uint8_t *msg, size_t len, const uint8_t *sig);

} // namespace ant2sign
} // namespace inet

#endif
