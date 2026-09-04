// gen_group_key.c
//
// Strumento OFFLINE: genera UNA volta la chiave simmetrica di gruppo (16 byte)
// da caricare identica su ogni nodo della flotta (droni + gateway + satellite).
//
// Uso:
//   ./gen_group_key group.key

#include <stdio.h>
#include "../crypto/ed25519/ed25519.h"   // riusiamo ed25519_create_seed come fonte di casualita' sicura

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <file_output>\n", argv[0]);
        return 1;
    }
    unsigned char randomBytes[32];
    if (ed25519_create_seed(randomBytes) != 0) {
        fprintf(stderr, "Errore nella generazione casuale\n");
        return 1;
    }
    FILE* f = fopen(argv[1], "wb");
    if (!f) { fprintf(stderr, "Impossibile creare %s\n", argv[1]); return 1; }
    fwrite(randomBytes, 1, 16, f);   // prendiamo solo i primi 16 byte: e' quanto serve ad Ascon-AEAD128
    fclose(f);
    printf("Chiave di gruppo da 16 byte scritta in %s\n", argv[1]);
    return 0;
}
