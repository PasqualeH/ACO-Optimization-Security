// =============================================================================
// microbench.cc
//
// Misura il costo computazionale delle primitive crittografiche usate dal
// livello di sicurezza di Ant2, sui payload di dimensione REALE del protocollo.
//
// Serve perche' OMNeT++ e' un simulatore a eventi discreti: le operazioni
// crittografiche vengono eseguite realmente, ma non consumano tempo simulato.
// La simulazione misura quindi l'overhead di BANDA, non quello di CPU.
// Combinando i tempi misurati qui con i conteggi di pacchetti prodotti dalla
// simulazione (file ant2_security_totals.txt) si ottiene una stima del carico
// computazionale per nodo.
//
// Compilazione (dalla cartella inet/src/inet/routing/ant2/):
//   g++ -std=c++14 -O2 -I. -c crypto/ascon/aead.cc -o mb_aead.o
//   g++ -std=c++14 -O2 -I. -c crypto/ascon/printstate.cc -o mb_printstate.o
//   g++ -std=c++14 -O2 -c crypto/ed25519/*.cc
//   g++ -std=c++14 -O2 -I. -c microbench.cc -o microbench.o
//   g++ -o microbench microbench.o mb_aead.o mb_printstate.o fe.o ge.o sc.o \
//        sha512.o sign.o verify.o keypair.o add_scalar.o seed.o
//   ./microbench
// =============================================================================

#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
#include <algorithm>

extern "C" {
    #include "crypto/ascon/crypto_aead.h"
}
#include "crypto/ed25519/ed25519.h"

using Clock = std::chrono::steady_clock;

// Dimensioni reali dei payload nel protocollo Ant2
static const size_t PT_BANT = 53;   // throughput+energy+x+y+z+maxband+cluster+flag
static const size_t PT_REQ  = 25;   // x+y+z+flag
static const size_t AAD_LEN = 12;   // srcAddress || dstAddress || sequencenumber
static const size_t FANT_SIGNED = 12; // srcAddress || dstAddress || sequencenumber

// Esegue 'iter' ripetizioni e restituisce il tempo MEDIANO per operazione, in
// microsecondi. Si usa la mediana e non la media perche' e' robusta rispetto
// agli outlier dovuti a interruzioni del sistema operativo.
template <typename F>
static double misura(F&& op, int iter, int campioni = 11)
{
    std::vector<double> tempi;
    tempi.reserve(campioni);
    for (int c = 0; c < campioni; c++) {
        auto t0 = Clock::now();
        for (int i = 0; i < iter; i++)
            op();
        auto t1 = Clock::now();
        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        tempi.push_back(us / iter);
    }
    std::sort(tempi.begin(), tempi.end());
    return tempi[tempi.size() / 2];
}

int main()
{
    // --- Preparazione dati di prova -----------------------------------------
    uint8_t key[16], nonce[16];
    for (int i = 0; i < 16; i++) { key[i] = i; nonce[i] = 255 - i; }

    std::vector<uint8_t> aad(AAD_LEN, 0xAB);
    std::vector<uint8_t> pt_bant(PT_BANT, 0x5A);
    std::vector<uint8_t> pt_req(PT_REQ, 0x5A);
    std::vector<uint8_t> ct_bant(PT_BANT + 16), ct_req(PT_REQ + 16);
    unsigned long long clen_bant = 0, clen_req = 0;

    unsigned char seed[32], pub[32], priv[64];
    for (int i = 0; i < 32; i++) seed[i] = i + 1;
    ed25519_create_keypair(pub, priv, seed);

    // Blocchi effettivamente firmati nel protocollo
    std::vector<uint8_t> fant_data(FANT_SIGNED, 0x11);              // 12 byte
    std::vector<uint8_t> bant_data(AAD_LEN + PT_BANT + 16, 0x22);   // 81 byte
    std::vector<uint8_t> req_data(AAD_LEN + PT_REQ + 16, 0x33);     // 53 byte

    uint8_t sig_fant[64], sig_bant[64], sig_req[64];
    ed25519_sign(sig_fant, fant_data.data(), fant_data.size(), pub, priv);
    ed25519_sign(sig_bant, bant_data.data(), bant_data.size(), pub, priv);
    ed25519_sign(sig_req,  req_data.data(),  req_data.size(),  pub, priv);

    // Cifrature di riferimento (per poter misurare la decifratura)
    crypto_aead_encrypt(ct_bant.data(), &clen_bant, pt_bant.data(), pt_bant.size(),
                        aad.data(), aad.size(), nullptr, nonce, key);
    crypto_aead_encrypt(ct_req.data(), &clen_req, pt_req.data(), pt_req.size(),
                        aad.data(), aad.size(), nullptr, nonce, key);

    printf("=====================================================================\n");
    printf(" MICRO-BENCHMARK delle primitive crittografiche di Ant2\n");
    printf(" Tempi MEDIANI per singola operazione, su questa macchina.\n");
    printf("=====================================================================\n\n");

    // --- Ascon-AEAD128 -------------------------------------------------------
    double enc_bant = misura([&]{
        unsigned long long l;
        crypto_aead_encrypt(ct_bant.data(), &l, pt_bant.data(), pt_bant.size(),
                            aad.data(), aad.size(), nullptr, nonce, key);
    }, 20000);

    double dec_bant = misura([&]{
        unsigned long long l;
        std::vector<uint8_t> out(PT_BANT);
        crypto_aead_decrypt(out.data(), &l, nullptr, ct_bant.data(), PT_BANT + 16,
                            aad.data(), aad.size(), nonce, key);
    }, 20000);

    double enc_req = misura([&]{
        unsigned long long l;
        crypto_aead_encrypt(ct_req.data(), &l, pt_req.data(), pt_req.size(),
                            aad.data(), aad.size(), nullptr, nonce, key);
    }, 20000);

    double dec_req = misura([&]{
        unsigned long long l;
        std::vector<uint8_t> out(PT_REQ);
        crypto_aead_decrypt(out.data(), &l, nullptr, ct_req.data(), PT_REQ + 16,
                            aad.data(), aad.size(), nonce, key);
    }, 20000);

    printf("--- Ascon-AEAD128 (confidenzialita' + integrita') -------------------\n");
    printf("  cifratura   payload BANT (53 B) : %8.3f us\n", enc_bant);
    printf("  decifratura payload BANT (53 B) : %8.3f us\n", dec_bant);
    printf("  cifratura   payload REQ  (25 B) : %8.3f us\n", enc_req);
    printf("  decifratura payload REQ  (25 B) : %8.3f us\n\n", dec_req);

    // --- Ed25519 -------------------------------------------------------------
    double sign_fant = misura([&]{
        uint8_t s[64];
        ed25519_sign(s, fant_data.data(), fant_data.size(), pub, priv);
    }, 2000);

    double ver_fant = misura([&]{
        ed25519_verify(sig_fant, fant_data.data(), fant_data.size(), pub);
    }, 2000);

    double sign_bant = misura([&]{
        uint8_t s[64];
        ed25519_sign(s, bant_data.data(), bant_data.size(), pub, priv);
    }, 2000);

    double ver_bant = misura([&]{
        ed25519_verify(sig_bant, bant_data.data(), bant_data.size(), pub);
    }, 2000);

    double sign_req = misura([&]{
        uint8_t s[64];
        ed25519_sign(s, req_data.data(), req_data.size(), pub, priv);
    }, 2000);

    double ver_req = misura([&]{
        ed25519_verify(sig_req, req_data.data(), req_data.size(), pub);
    }, 2000);

    printf("--- Ed25519 (autenticazione dell'origine) ---------------------------\n");
    printf("  firma    blocco FANT (12 B)     : %8.3f us\n", sign_fant);
    printf("  verifica blocco FANT (12 B)     : %8.3f us\n", ver_fant);
    printf("  firma    blocco BANT (81 B)     : %8.3f us\n", sign_bant);
    printf("  verifica blocco BANT (81 B)     : %8.3f us\n", ver_bant);
    printf("  firma    blocco REQ  (53 B)     : %8.3f us\n", sign_req);
    printf("  verifica blocco REQ  (53 B)     : %8.3f us\n\n", ver_req);

    // --- Costo complessivo per messaggio -------------------------------------
    printf("--- Costo COMPLESSIVO per messaggio ---------------------------------\n");
    printf("  (invio = cifratura + firma; ricezione = verifica + decifratura)\n\n");
    printf("  FANT  invio     : %8.3f us   (solo firma)\n", sign_fant);
    printf("  FANT  ricezione : %8.3f us   (solo verifica)\n", ver_fant);
    printf("  BANT  invio     : %8.3f us\n", enc_bant + sign_bant);
    printf("  BANT  ricezione : %8.3f us\n", ver_bant + dec_bant);
    printf("  REQ   invio     : %8.3f us\n", enc_req + sign_req);
    printf("  REQ   ricezione : %8.3f us\n\n", ver_req + dec_req);

    printf("--- Osservazione ----------------------------------------------------\n");
    double rapporto = ver_bant / dec_bant;
    printf("  La verifica di una firma Ed25519 costa circa %.0f volte piu' della\n", rapporto);
    printf("  decifratura Ascon dello stesso messaggio: il costo computazionale\n");
    printf("  del livello di sicurezza e' dominato dalla parte asimmetrica.\n\n");

    printf("--- Come usare questi numeri ----------------------------------------\n");
    printf("  Moltiplicare i tempi di RICEZIONE per i conteggi riportati in\n");
    printf("  ant2_security_totals.txt per ottenere il tempo di CPU speso da\n");
    printf("  ciascun nodo in operazioni crittografiche durante la simulazione.\n");
    printf("=====================================================================\n");

    return 0;
}
