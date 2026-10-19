// Ant2Aead.h
//
// Strato di adattamento che espone UNA SOLA interfaccia per i sette algoritmi
// AEAD messi a confronto nella tesi:
//
//   - Ascon-AEAD128        (NIST SP 800-232)       chiave 16 B, nonce 16 B, tag 16 B
//   - AES-128-GCM          (FIPS 197 + SP 800-38D) chiave 16 B, nonce 12 B, tag 16 B
//   - AES-192-GCM                                  chiave 24 B, nonce 12 B, tag 16 B
//   - AES-256-GCM                                  chiave 32 B, nonce 12 B, tag 16 B
//   - ChaCha20-Poly1305    (RFC 8439)              chiave 32 B, nonce 12 B, tag 16 B
//   - Xoodyak              (finalista NIST LWC)    chiave 16 B, nonce 16 B, tag 16 B
//   - TinyJAMBU-128        (finalista NIST LWC)    chiave 16 B, nonce 12 B, tag  8 B
//
// Tutti sono "length-preserving" (ciphertext della stessa lunghezza del
// plaintext). I primi sei producono un tag da 16 byte, quindi con loro i
// messaggi BantM2/ReqM2 hanno sempre la stessa dimensione. TinyJAMBU-128 ha
// invece un tag da 8 byte: per questo la lunghezza del tag NON e' piu' una
// costante ma si legge con tagLen(alg), e BANT/REQ protetti con TinyJAMBU sono
// 8 byte piu' corti (BANT 145 B invece di 153, REQ 113 B invece di 121).
//
// Le implementazioni concrete stanno in crypto/ascon (gia' presente), in
// crypto/aead (Arduino Cryptography Library di Rhys Weatherley, licenza MIT) e
// in crypto/xoodyak, crypto/tinyjambu, crypto/lwc-common (libreria
// "lwc-finalists" dello stesso autore, licenza MIT, versioni del round finale).
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
    CHACHA20POLY1305,
    // Aggiunti IN CODA, cosi' i valori numerici dei cinque algoritmi gia'
    // esistenti restano identici a prima.
    XOODYAK,
    TINYJAMBU128
};

// Lunghezza massima fra tutti gli algoritmi: serve a dimensionare i buffer
// statici in Ant2Crypto senza doverli allocare dinamicamente.
static const int MAX_KEY_LEN   = 32;
static const int MAX_NONCE_LEN = 16;
// Non esiste piu' una costante TAG_LEN unica: e' stata rimossa di proposito,
// cosi' il compilatore segnala ogni punto del codice che la usava e nessuno
// puo' restare a presumere "16" per sbaglio. Per dimensionare i buffer si usa
// MAX_TAG_LEN (caso peggiore); per sapere quanti byte usare davvero, tagLen().
static const int MAX_TAG_LEN   = 16;

// Converte il nome usato nel file .ini nell'enum. Ritorna false se il nome non
// e' riconosciuto (il chiamante deve fermare la simulazione con un errore
// chiaro: meglio non partire che partire con un algoritmo diverso da quello
// che si crede di stare misurando).
bool parseName(const std::string& name, Algorithm& out);

const char *name(Algorithm alg);
int keyLen(Algorithm alg);
int nonceLen(Algorithm alg);
// Lunghezza del tag di autenticazione: 16 B per tutti tranne TinyJAMBU-128 (8 B).
int tagLen(Algorithm alg);

// Cifra 'ptLen' byte. 'ct' deve avere spazio per 'ptLen' byte, 'tag' per
// tagLen(alg) byte (un buffer di MAX_TAG_LEN byte va sempre bene).
bool encrypt(Algorithm alg,
             const uint8_t *key, const uint8_t *nonce,
             const uint8_t *aad, size_t aadLen,
             const uint8_t *pt, size_t ptLen,
             uint8_t *ct, uint8_t *tag);

// Decifra e verifica il tag ('tag' deve contenere tagLen(alg) byte).
// Ritorna false se il tag non e' valido: in quel
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
