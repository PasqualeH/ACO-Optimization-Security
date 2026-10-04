// Ant2Aead.h
//
// Strato di adattamento che espone UNA SOLA interfaccia per i cinque algoritmi
// AEAD messi a confronto nella tesi:
//
//   - Ascon-AEAD128        (NIST SP 800-232)   chiave 16 B, nonce 16 B
//   - AES-128-GCM          (FIPS 197 + SP 800-38D) chiave 16 B, nonce 12 B
//   - AES-192-GCM                                   chiave 24 B, nonce 12 B
//   - AES-256-GCM                                   chiave 32 B, nonce 12 B
//   - ChaCha20-Poly1305    (RFC 8439)          chiave 32 B, nonce 12 B
//
// Tutti e cinque producono un tag da 16 byte e sono "length-preserving"
// (ciphertext della stessa lunghezza del plaintext): per questo il formato dei
// messaggi BantM2/ReqM2 NON cambia al variare dell'algoritmo, e le misure di
// overhead di banda gia' fatte restano valide.
//
// Le implementazioni concrete stanno in crypto/ascon (gia' presente) e in
// crypto/aead (Arduino Cryptography Library di Rhys Weatherley, licenza MIT).
// Sono deliberatamente implementazioni SOFTWARE, senza istruzioni AES-NI:
// il bersaglio del progetto e' un drone con microcontrollore, non un x86.

#ifndef __INET_ANT2AEAD_H
#define __INET_ANT2AEAD_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace inet {
namespace ant2aead {

enum Algorithm {
    ASCON128 = 0,
    AES128GCM,
    AES192GCM,
    AES256GCM,
    CHACHA20POLY1305
};

// Lunghezza massima fra tutti gli algoritmi: serve a dimensionare i buffer
// statici in Ant2Crypto senza doverli allocare dinamicamente.
static const int MAX_KEY_LEN   = 32;
static const int MAX_NONCE_LEN = 16;
static const int TAG_LEN       = 16;   // uguale per tutti e cinque

// Converte il nome usato nel file .ini nell'enum. Ritorna false se il nome non
// e' riconosciuto (il chiamante deve fermare la simulazione con un errore
// chiaro: meglio non partire che partire con un algoritmo diverso da quello
// che si crede di stare misurando).
bool parseName(const std::string& name, Algorithm& out);

const char *name(Algorithm alg);
int keyLen(Algorithm alg);
int nonceLen(Algorithm alg);

// Cifra 'ptLen' byte. 'ct' deve avere spazio per 'ptLen' byte, 'tag' per 16.
bool encrypt(Algorithm alg,
             const uint8_t *key, const uint8_t *nonce,
             const uint8_t *aad, size_t aadLen,
             const uint8_t *pt, size_t ptLen,
             uint8_t *ct, uint8_t *tag);

// Decifra e verifica il tag. Ritorna false se il tag non e' valido: in quel
// caso il contenuto di 'pt' non va usato.
bool decrypt(Algorithm alg,
             const uint8_t *key, const uint8_t *nonce,
             const uint8_t *aad, size_t aadLen,
             const uint8_t *ct, size_t ctLen,
             const uint8_t *tag,
             uint8_t *pt);

} // namespace ant2aead
} // namespace inet

#endif
