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
// 'coordenates' e 'allowed_accept_request' sono dati sensibili (la posizione
// di un drone in difficolta', e se un candidato e' disponibile): vanno cifrati.
// hopAddresses[] resta in chiaro: cambia ad ogni hop, non puo' essere protetto
// dalla firma del mittente originale (vedi nota nel documento di design, §7).

import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;
import inet.networklayer.contract.ipv4.Ipv4Address;

namespace inet;

class ReqM2 extends FieldsChunk
{
    // --- Campi di routing: in chiaro, autenticati come AAD.
    Ipv4Address srcAddress;
    Ipv4Address dstAddress;
    unsigned int sequencenumber;
    Ipv4Address nextAddress;
    int hopdistance;

    // --- Metadato di inoltro: muta ad ogni hop, non autenticato (limite noto, §7 del design doc).
    Ipv4Address hopAddresses[];

    // --- Payload cifrato: coordenates (3 double x/y/z) + allowed_accept_request.
    uint8_t ciphertext[];
    // Tag AEAD a lunghezza variabile: 16 byte, oppure 8 con TinyJAMBU-128 (vedi BantM2.msg).
    uint8_t authTag[];

    // --- Firma Ed25519 del mittente originale.
    uint8_t signature[64];
}
