//
// Copyright (C) 2008
//
// DSDV simple example for INET (add-on)
// Version 1.0
// Diogo Antio & Pedro Menezes
// Instituto Superior Tecnico
// Lisboa - Portugal
//
// --- MODIFICATO: livello di sicurezza (AEAD configurabile + firma Ed25519/ECDSA) ---
// I campi sensibili (energia, throughput, coordinate, cluster_id, ecc.)
// NON sono piu' campi in chiaro: vengono impacchettati, cifrati e
// autenticati prima dell'invio, e viaggiano solo dentro 'ciphertext'.
// Restano in chiaro solo i campi indispensabili all'inoltro (routing),
// che pero' sono comunque autenticati come AAD (Associated Data) dal tag/firma.

import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;
import inet.networklayer.contract.ipv4.Ipv4Address;

namespace inet;

class BantM2 extends FieldsChunk
{
    // --- Campi di routing: restano in chiaro, servono ad ogni hop per l'inoltro.
    // Sono comunque autenticati (AAD): un nodo intermedio non puo' alterarli
    // senza far fallire la verifica della firma del mittente originale.
    Ipv4Address srcAddress;
    Ipv4Address dstAddress;
    Ipv4Address gateway;
    unsigned int sequencenumber;
    Ipv4Address nextAddress;
    int hopdistance;

    // --- Payload cifrato: qui dentro, impacchettati e cifrati con Ascon-AEAD128,
    // viaggiano i campi che nella versione originale erano in chiaro:
    // throughput, energy, coordenates (convertite in 3 double x/y/z),
    // hops, max_throughput, cluster_id, allowed_accept_request.
    uint8_t ciphertext[];       // lunghezza = lunghezza del payload in chiaro (tutti gli AEAD usati sono "length-preserving")
    // Tag di autenticazione dell'AEAD configurato. Array DINAMICO (prima era
    // authTag[16]): la sua lunghezza dipende dall'algoritmo, 16 byte per
    // Ascon/AES-GCM/ChaCha20-Poly1305/Xoodyak e 8 byte per TinyJAMBU-128.
    // Chi costruisce il messaggio chiama setAuthTagArraySize(crypto.tagLen());
    // chi lo riceve controlla che getAuthTagArraySize() sia quella attesa.
    uint8_t authTag[];

    // --- Autenticazione del mittente: firma Ed25519 su srcAddress||sequencenumber||ciphertext||authTag.
    // Chi non ha la chiave privata del nodo dichiarato in srcAddress non puo' produrla.
    uint8_t signature[64];      // firma Ed25519 (64 byte fissi)
}
