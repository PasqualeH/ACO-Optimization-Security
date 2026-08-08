//
// Copyright (C) 2008
//
// DSDV simple example for INET (add-on)
// Version 1.0
// Diogo Antio & Pedro Menezes
// Instituto Superior Tecnico
// Lisboa - Portugal
//
// --- MODIFICATO: livello di sicurezza (Ed25519) ---
// Il FANT non trasporta alcun dato sensibile (e' solo un "hello"/scoperta
// di rotta): non serve cifrarlo con Ascon, basta autenticarlo con la firma
// del mittente, per impedire che un nodo non autorizzato lo inietti.

import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;
import inet.networklayer.contract.ipv4.Ipv4Address;

namespace inet;

class FantM2 extends FieldsChunk
{
    // --- Campi di routing: in chiaro, autenticati (coperti dalla firma).
    Ipv4Address srcAddress;
    Ipv4Address dstAddress;
    unsigned int sequencenumber;
    Ipv4Address nextAddress;

    // --- Metadati di inoltro: mutano ad ogni hop, non autenticati (limite noto, §7 del design doc).
    int hopdistance;
    Ipv4Address hopAddresses[];

    // --- Firma Ed25519 del mittente originale su srcAddress||dstAddress||sequencenumber.
    uint8_t signature[64];
}
