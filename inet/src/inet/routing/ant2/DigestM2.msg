//
// DigestM2.msg - bollettino che una GCS pubblica nel proprio cluster.
//
// Serve alla regola 0 della metrica di trust (coerenza fra canali). A ogni
// chiusura di un giro di tracce la GCS manda ai droni del proprio cluster le
// impronte crittografiche delle letture che ha ricevuto, piu' il registro dei
// REQ che ha osservato. I droni confrontano quelle impronte con quelle delle
// letture che hanno ricevuto loro: se per la stessa lettura le impronte non
// coincidono, il drone osservato ha dichiarato due cose diverse, ed e' una
// violazione certa.
//
// A differenza dello snapshot fra GCS, questo messaggio viaggia DENTRO il
// canale del cluster (wlan1), perche' i destinatari sono i droni. E' il canale
// congestionato, ed e' il motivo per cui si mandano impronte da 8 byte invece
// dei valori: un record completo ne occuperebbe 148.
//
// Il contenuto e' diviso in sezioni, ciascuna con il proprio tipo e il proprio
// numero di record, cosi' che la sezione degli hop possa essere aggiunta in
// seguito senza cambiare il formato. Formato dei record: Ant2DigestCheck.h,
// sotto-spazio di nomi ant2digest::wire.
//

import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;
import inet.networklayer.contract.ipv4.Ipv4Address;

namespace inet;

class DigestM2 extends FieldsChunk
{
    Ipv4Address origin;       // GCS che ha prodotto il bollettino
    unsigned int giro;        // numero del giro di tracce
    unsigned int contatore;   // contatore dei bollettini della GCS: nonce, e
                              // permette a un drone di accorgersi dei buchi
    double istante;           // istante di emissione
    int cluster;              // cluster della GCS
    int numByte;              // lunghezza del contenuto in chiaro
    uint8_t payload[];        // sezioni cifrate
    uint8_t authTag[];        // tag AEAD
    uint8_t signature[64];    // firma della GCS
}
