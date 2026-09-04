// gen_node_keypair.c
//
// Strumento OFFLINE (da eseguire una volta per nodo, PRIMA della missione,
// mai dentro la simulazione) per generare una coppia di chiavi Ed25519.
//
// Uso:
//   ./gen_node_keypair <indirizzo_ipv4_intero> <cartella_output> <file_roster>
//
// Esempio:
//   ./gen_node_keypair 167772161 keys/ roster.txt
//
// Produce:
//   <cartella_output>/<indirizzo>_pub.bin   (32 byte)
//   <cartella_output>/<indirizzo>_priv.bin  (64 byte, da tenere SOLO sul nodo)
//   e AGGIUNGE una riga al file di roster condiviso da tutta la flotta:
//   "<indirizzo> <chiave_pubblica_in_hex>"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../crypto/ed25519/ed25519.h"

int main(int argc, char** argv) {
    if (argc != 4) {
        fprintf(stderr, "Uso: %s <indirizzo_ipv4_intero> <cartella_output> <file_roster>\n", argv[0]);
        return 1;
    }
    const char* addr = argv[1];
    const char* outDir = argv[2];
    const char* rosterPath = argv[3];

    unsigned char seed[32];
    if (ed25519_create_seed(seed) != 0) {
        fprintf(stderr, "Errore nella generazione del seed casuale\n");
        return 1;
    }

    unsigned char pub[32], priv[64];
    ed25519_create_keypair(pub, priv, seed);

    char pubPath[512], privPath[512];
    snprintf(pubPath, sizeof(pubPath), "%s/%s_pub.bin", outDir, addr);
    snprintf(privPath, sizeof(privPath), "%s/%s_priv.bin", outDir, addr);

    FILE* fp = fopen(pubPath, "wb");
    if (!fp) { fprintf(stderr, "Impossibile creare %s\n", pubPath); return 1; }
    fwrite(pub, 1, 32, fp);
    fclose(fp);

    FILE* fs = fopen(privPath, "wb");
    if (!fs) { fprintf(stderr, "Impossibile creare %s\n", privPath); return 1; }
    fwrite(priv, 1, 64, fs);
    fclose(fs);

    FILE* fr = fopen(rosterPath, "a");
    if (!fr) { fprintf(stderr, "Impossibile aprire %s\n", rosterPath); return 1; }
    fprintf(fr, "%s ", addr);
    for (int i = 0; i < 32; i++) fprintf(fr, "%02x", pub[i]);
    fprintf(fr, "\n");
    fclose(fr);

    printf("Nodo %s: chiavi generate (%s, %s), pubkey aggiunta a %s\n", addr, pubPath, privPath, rosterPath);
    return 0;
}
