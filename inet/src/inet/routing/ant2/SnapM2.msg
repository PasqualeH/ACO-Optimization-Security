//
// SnapM2.msg - snapshot del cluster di una GCS, inviato alle altre GCS.
//
// A ogni chiusura di un giro di tracce, ogni GCS invia alle altre il proprio
// snapshot: per ogni nodo del suo cluster, gli ultimi dati raccolti con le
// tracce (parametri dei BANT, vicini), il numero di hop dalla GCS e il
// percorso. Il contenuto e' cifrato con la chiave di gruppo e firmato dalla
// GCS. Viaggia sulla rete tra GCS e satellite in broadcast: lo inoltrano solo
// i nodi con snapshotRelay = true (GCS e satellite), una volta ciascuno.
// Formato dei record: Ant2Trace.h (SnapRecord).
//

import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;
import inet.networklayer.contract.ipv4.Ipv4Address;

namespace inet;

class SnapM2 extends FieldsChunk
{
    Ipv4Address origin;       // GCS che ha prodotto lo snapshot
    unsigned int giro;        // numero del giro di tracce
    unsigned int contatore;   // contatore degli snapshot della GCS (nonce)
    double istante;           // istante di chiusura del giro
    int cluster;              // cluster della GCS
    int numRecord;            // numero di nodi
    uint8_t payload[];        // record cifrati (numRecord * SNAP_REC_LEN byte)
    uint8_t authTag[];        // tag AEAD
    uint8_t signature[64];    // firma della GCS
}
