//
// TraceM2.msg - traceroute delle GCS (snapshot della rete).
//
// La GCS ("origine") invia una traccia verso un nodo ("bersaglio"). La traccia
// segue la tabella di routing dei nodi: ogni nodo che la riceve aggiunge una
// propria voce (cifrata con la chiave di gruppo e firmata, a catena con la
// voce precedente) e la passa al vicino che la sua tabella indica per il
// bersaglio. Il bersaglio aggiunge la sua voce e la rimanda indietro lungo lo
// stesso percorso, al contrario, fino alla GCS.
// Formato e significato delle voci: Ant2Trace.h.
//

import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;
import inet.networklayer.contract.ipv4.Ipv4Address;

namespace inet;

class TraceM2 extends FieldsChunk
{
    Ipv4Address origin;          // GCS che ha lanciato la traccia (firma originSignature)
    Ipv4Address target;          // nodo bersaglio
    unsigned int traceId;        // identificativo della traccia presso la GCS
    Ipv4Address receiver;        // nodo a cui e' destinata QUESTA trasmissione (gli altri la ignorano)
    int hopdistance;             // in chiaro, incrementato a ogni passaggio come negli altri messaggi
    bool ritorno;                // false = andata verso il bersaglio, true = ritorno verso la GCS
    uint8_t esito;               // vedi ant2trace::Esito (completa, rotta mancante, limite hop, ciclo)
    uint8_t originSignature[64]; // firma della GCS su (origin, target, traceId)
    int numEntries;              // numero di voci
    uint8_t entries[];           // voci concatenate, ognuna di ant2trace::entryWireLen() byte
}
