// =============================================================================
// microbench.cc
//
// Misura il costo computazionale delle primitive crittografiche usate dal
// livello di sicurezza di Ant2, sui payload di dimensione REALE del protocollo.
//
// PERCHE' SERVE UN PROGRAMMA A PARTE, E NON LA SIMULAZIONE
// -------------------------------------------------------
// OMNeT++ e' un simulatore a eventi discreti: il tempo simulato avanza solo
// quando viene programmato un evento. Le chiamate a cifratura, firma e verifica
// vengono eseguite davvero dalla CPU, ma non "consumano" tempo simulato: per il
// simulatore sono istantanee. La simulazione misura quindi correttamente
// l'overhead di BANDA (byte in piu' sui pacchetti) ma NON quello di CPU.
// Questo programma colma quella lacuna misurando i tempi reali, e i risultati
// si combinano con i conteggi di pacchetti prodotti dalla simulazione
// (ant2_security_totals_rN.txt) per stimare il carico per nodo.
//
// COSA MISURA E COME
// ------------------
// Non usa nessun dato preso da internet: esegue le stesse identiche funzioni
// che gira il protocollo, sugli stessi dati, e le cronometra. Per ogni
// operazione:
//   - esegue 'iter' ripetizioni consecutive e divide il tempo totale per iter
//     (una singola operazione dura pochi microsecondi, sotto la risoluzione
//     utile dell'orologio: misurarne una sola darebbe un numero senza senso);
//   - ripete l'intero blocco 'campioni' volte e tiene la MEDIANA, che e'
//     robusta rispetto alle interruzioni del sistema operativo (se il kernel
//     toglie la CPU per un millisecondo in mezzo a un blocco, quel campione
//     diventa un valore anomalo: la mediana lo ignora, la media no).
// I numeri dipendono dalla macchina su cui si esegue: vanno riportati in tesi
// indicando il processore, e usati soprattutto come RAPPORTI fra algoritmi,
// che sono molto piu' stabili dei valori assoluti.
//
// Le implementazioni sono tutte SOFTWARE: nessuna usa le istruzioni AES-NI del
// processore. E' una scelta voluta, perche' il bersaglio del progetto e' un
// drone con microcontrollore (senza acceleratore AES), non un x86.
//
// Compilazione (dalla cartella inet/src/inet/routing/ant2/):
//   g++ -std=c++17 -O2 -I. -I../../.. -o microbench microbench.cc \
//       Ant2Aead.cc crypto/ascon/*.cc crypto/aead/*.cc crypto/ed25519/*.cc
//   ./microbench
// =============================================================================

#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
#include <algorithm>

#include "inet/routing/ant2/Ant2Aead.h"
#include "inet/routing/ant2/Ant2Sign.h"
#include "crypto/ed25519/ed25519.h"

using Clock = std::chrono::steady_clock;
using namespace inet;

// Dimensioni reali dei payload nel protocollo Ant2
static const size_t PT_BANT = 53;     // throughput+energy+x+y+z+maxband+cluster+flag
static const size_t PT_REQ  = 25;     // x+y+z+flag
static const size_t AAD_LEN = 12;     // srcAddress || dstAddress || sequencenumber
static const size_t FANT_SIGNED = 12; // srcAddress || dstAddress || sequencenumber

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
        tempi.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count() / iter);
    }
    std::sort(tempi.begin(), tempi.end());
    return tempi[tempi.size() / 2];
}

struct Risultato {
    const char *nome;
    double encBant, decBant, encReq, decReq;
};

static Risultato benchAead(ant2aead::Algorithm alg)
{
    uint8_t key[ant2aead::MAX_KEY_LEN], nonce[ant2aead::MAX_NONCE_LEN];
    for (int i = 0; i < ant2aead::MAX_KEY_LEN; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < ant2aead::MAX_NONCE_LEN; i++) nonce[i] = (uint8_t)(255 - i);

    std::vector<uint8_t> aad(AAD_LEN, 0xAB);
    std::vector<uint8_t> ptBant(PT_BANT, 0x5A), ptReq(PT_REQ, 0x5A);
    std::vector<uint8_t> ctBant(PT_BANT), ctReq(PT_REQ);
    std::vector<uint8_t> outBant(PT_BANT), outReq(PT_REQ);
    uint8_t tagBant[16], tagReq[16];

    // Cifrature di riferimento, per poter poi misurare la decifratura
    ant2aead::encrypt(alg, key, nonce, aad.data(), aad.size(),
                      ptBant.data(), PT_BANT, ctBant.data(), tagBant);
    ant2aead::encrypt(alg, key, nonce, aad.data(), aad.size(),
                      ptReq.data(), PT_REQ, ctReq.data(), tagReq);

    Risultato r;
    r.nome = ant2aead::name(alg);
    r.encBant = misura([&]{ uint8_t t[16];
        ant2aead::encrypt(alg, key, nonce, aad.data(), aad.size(),
                          ptBant.data(), PT_BANT, ctBant.data(), t); }, 20000);
    r.decBant = misura([&]{
        ant2aead::decrypt(alg, key, nonce, aad.data(), aad.size(),
                          ctBant.data(), PT_BANT, tagBant, outBant.data()); }, 20000);
    r.encReq  = misura([&]{ uint8_t t[16];
        ant2aead::encrypt(alg, key, nonce, aad.data(), aad.size(),
                          ptReq.data(), PT_REQ, ctReq.data(), t); }, 20000);
    r.decReq  = misura([&]{
        ant2aead::decrypt(alg, key, nonce, aad.data(), aad.size(),
                          ctReq.data(), PT_REQ, tagReq, outReq.data()); }, 20000);
    return r;
}

#ifdef ANT2_MICROBENCH_STANDALONE

int main()
{
    printf("=====================================================================\n");
    printf(" MICRO-BENCHMARK delle primitive crittografiche di Ant2\n");
    printf(" Tempi MEDIANI per singola operazione, misurati su QUESTA macchina.\n");
    printf(" Implementazioni software (nessuna istruzione AES-NI).\n");
    printf("=====================================================================\n\n");

    const ant2aead::Algorithm algs[] = {
        ant2aead::ASCON128, ant2aead::AES128GCM, ant2aead::AES192GCM,
        ant2aead::AES256GCM, ant2aead::CHACHA20POLY1305
    };

    printf("--- AEAD: confidenzialita' + integrita' -------------------------------------\n");
    printf("%-20s %6s %6s | %11s %11s | %11s %11s\n",
           "algoritmo", "chiave", "nonce", "cifra 53B", "decifra 53B", "cifra 25B", "decifra 25B");
    std::vector<Risultato> risultati;
    for (auto a : algs) {
        Risultato r = benchAead(a);
        risultati.push_back(r);
        printf("%-20s %4d B %4d B | %8.3f us %8.3f us | %8.3f us %8.3f us\n",
               r.nome, ant2aead::keyLen(a), ant2aead::nonceLen(a),
               r.encBant, r.decBant, r.encReq, r.decReq);
    }

    // --- Firme: Ed25519 e ECDSA P-256 ---------------------------------------
    unsigned char seed[32];
    for (int i = 0; i < 32; i++) seed[i] = i + 1;
    unsigned char pub[ant2sign::MAX_PUBKEY_LEN] = {0};
    unsigned char priv[ant2sign::MAX_PRIVKEY_LEN] = {0};
    ant2sign::generateKeypair(ant2sign::ED25519, seed, pub, priv);

    std::vector<uint8_t> fantData(FANT_SIGNED, 0x11);            // 12 B
    std::vector<uint8_t> bantData(AAD_LEN + PT_BANT + 16, 0x22); // 81 B
    std::vector<uint8_t> reqData(AAD_LEN + PT_REQ + 16, 0x33);   // 53 B
    uint8_t sigFant[64], sigBant[64], sigReq[64];
    ed25519_sign(sigFant, fantData.data(), fantData.size(), pub, priv);
    ed25519_sign(sigBant, bantData.data(), bantData.size(), pub, priv);
    ed25519_sign(sigReq,  reqData.data(),  reqData.size(),  pub, priv);

    double signFant = misura([&]{ uint8_t s[64]; ed25519_sign(s, fantData.data(), fantData.size(), pub, priv); }, 2000);
    double verFant  = misura([&]{ ed25519_verify(sigFant, fantData.data(), fantData.size(), pub); }, 2000);
    double signBant = misura([&]{ uint8_t s[64]; ed25519_sign(s, bantData.data(), bantData.size(), pub, priv); }, 2000);
    double verBant  = misura([&]{ ed25519_verify(sigBant, bantData.data(), bantData.size(), pub); }, 2000);
    double signReq  = misura([&]{ uint8_t s[64]; ed25519_sign(s, reqData.data(), reqData.size(), pub, priv); }, 2000);
    double verReq   = misura([&]{ ed25519_verify(sigReq, reqData.data(), reqData.size(), pub); }, 2000);

    printf("\n--- Ed25519: autenticazione dell'origine ----------------------------\n");
    printf("  firma    blocco FANT (12 B)     : %8.3f us\n", signFant);
    printf("  verifica blocco FANT (12 B)     : %8.3f us\n", verFant);
    printf("  firma    blocco BANT (81 B)     : %8.3f us\n", signBant);
    printf("  verifica blocco BANT (81 B)     : %8.3f us\n", verBant);
    printf("  firma    blocco REQ  (53 B)     : %8.3f us\n", signReq);
    printf("  verifica blocco REQ  (53 B)     : %8.3f us\n", verReq);

    // --- Costo complessivo per messaggio, per ogni AEAD ----------------------
    // ECDSA P-256 sugli stessi blocchi
    unsigned char pubE[ant2sign::MAX_PUBKEY_LEN] = {0};
    unsigned char privE[ant2sign::MAX_PRIVKEY_LEN] = {0};
    ant2sign::generateKeypair(ant2sign::ECDSA_P256, seed, pubE, privE);
    uint8_t sigE[64];
    ant2sign::sign(ant2sign::ECDSA_P256, privE, pubE, bantData.data(), bantData.size(), sigE);

    double signBantE = misura([&]{ uint8_t s2[64];
        ant2sign::sign(ant2sign::ECDSA_P256, privE, pubE, bantData.data(), bantData.size(), s2); }, 500);
    double verBantE  = misura([&]{
        ant2sign::verify(ant2sign::ECDSA_P256, pubE, bantData.data(), bantData.size(), sigE); }, 500);

    printf("\n--- ECDSA P-256 con SHA-256: autenticazione dell'origine -------------\n");
    printf("  firma    blocco BANT (81 B)     : %8.3f us   (%.1fx Ed25519)\n", signBantE, signBantE / signBant);
    printf("  verifica blocco BANT (81 B)     : %8.3f us   (%.1fx Ed25519)\n", verBantE, verBantE / verBant);
    printf("  chiavi: pubblica 64 B, privata 32 B, firma 64 B\n");
    printf("  Nota: ECDSA richiede un valore casuale fresco a ogni firma; Ed25519\n");
    printf("  e' deterministico e non ha questo requisito.\n");

    printf("\n--- Costo COMPLESSIVO per un BANT, per algoritmo ---------------------\n");
    printf("  (invio = cifra + firma; ricezione = verifica + decifra)\n\n");
    printf("%-20s %14s %14s %12s\n", "AEAD + Ed25519", "invio", "ricezione", "quota AEAD");
    for (auto& r : risultati) {
        double invio = r.encBant + signBant;
        double ricez = r.decBant + verBant;
        printf("%-20s %11.3f us %11.3f us %10.1f %%\n",
               r.nome, invio, ricez, 100.0 * r.decBant / ricez);
    }
    printf("\n%-20s %14s %14s %12s\n", "AEAD + ECDSA-P256", "invio", "ricezione", "quota AEAD");
    for (auto& r : risultati) {
        double invio = r.encBant + signBantE;
        double ricez = r.decBant + verBantE;
        printf("%-20s %11.3f us %11.3f us %10.1f %%\n",
               r.nome, invio, ricez, 100.0 * r.decBant / ricez);
    }

    printf("\n--- Osservazione ----------------------------------------------------\n");
    printf("  La verifica di una firma Ed25519 costa da %.0f a %.0f volte piu' della\n",
           verBant / risultati[3].decBant, verBant / risultati[0].decBant);
    printf("  decifratura AEAD dello stesso messaggio. Il costo computazionale del\n");
    printf("  livello di sicurezza e' dominato dalla parte asimmetrica: la scelta\n");
    printf("  dell'AEAD sposta il totale di pochi punti percentuali.\n\n");

    printf("--- Come usare questi numeri ----------------------------------------\n");
    printf("  Moltiplicare i tempi di RICEZIONE per i conteggi riportati in\n");
    printf("  ant2_security_totals_rN.txt per ottenere il tempo di CPU speso da\n");
    printf("  ciascun nodo in operazioni crittografiche durante la simulazione.\n");
    printf("=====================================================================\n");
    return 0;
}

#endif // ANT2_MICROBENCH_STANDALONE
