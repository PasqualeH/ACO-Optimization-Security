//
// Copyright (C) 2009 by Alfonso Ariza, Malaga University
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// 

package inet.routing.ant2;
import inet.routing.contract.IManetRouting;

simple Ant2 like IManetRouting
{
    parameters:
        @class("ant2::Ant2");
        @display("i=block/routing");
        string interfaceTableModule;   // The path to the InterfaceTable module
        string routingTableModule;
        double helloInterval @unit(s);  // How often Fant messages should be sent out
        string netmask = default("255.255.0.0");  // Netmask for the ad-hoc network
        double maxVariance = default(1); // This is the maximum of a random value to determine when the first hello message will be sent out
        double routeLifetime @unit(s);  // The expiry time of the routing entries
        bool manetPurgeRoutingTables = default(true);
        volatile double broadcastDelay @unit(s) = default(uniform(0s,0.001s)); // Delay to broadcast messages and avoid collisions
        
        // Added for ACO algorithm
        double alpha = default(1.0); // Incidence factor of the pheromone
        double betaa = default(1.0); // Incidence factor of the Heuristics
        double pheromoneDecayRate = default(1.0); // Decay rate of pheromones
        double initialPheromoneValue = default(1.0); // Initial pheromone value
        double pheromoneIncrement = default(1.0); // Increment value of heromones
        
        
        double update_pheromone_Interval @unit(s);  // How often the pheromones decay
        double update_throughput_Interval @unit(s);  // How often the metrics (throughput, energy, coordinates, etc) are updated
        
        // Added to monitor the traffic passing though a node
        string networkProtocolModule = default("^.ipv4.ip");
        
        // Added for recruiting algorithm
        bool allowed_accept_request = default(false);
        bool allowed_send_request = default(true);
        
        // Added for energy consumption monitoring
        // Con legacyEnergy = false (default) NON e' piu' usato: la percentuale
        // si calcola sulla capacita' reale della batteria (energyStorage).
        double nominalCapacity;

        // Correzioni sull'energia (batteria, decimali, timbro di misura, ricarica).
        // legacyEnergy = true ripristina ESATTAMENTE il comportamento originale:
        // percentuale su nominalCapacity troncata all'intero, BANT senza timbro,
        // blocco dei timer al 15% e nessuna ricarica. Deve avere lo stesso
        // valore su tutti i nodi (cambia il formato del payload del BANT).
        bool legacyEnergy = default(false);
        double chargeThreshold = default(15);       // % sotto cui il drone va a ricaricarsi
        double chargeFullThreshold = default(100);  // % a cui la ricarica e' completata
        double chargingStationX @unit(m) = default(1000m);
        double chargingStationY @unit(m) = default(1000m);
        double chargingStationZ @unit(m) = default(50m);
        // Tempo tra l'avviso di batteria scarica e lo spostamento alla
        // stazione: l'avviso parte dalla posizione del drone, cosi' i vicini lo
        // ricevono e lo inoltrano a tutta la rete prima che il drone si
        // allontani (la stazione e' fuori dalla portata radio della flotta).
        double chargeDepartureDelay @unit(s) = default(1s);

        // Regola 1 della metrica di trust: controllo sull'energia dichiarata
        // nei BANT (attivo solo con legacyEnergy = false, che fornisce timbro
        // e decimali). Esiti nel file ant2_energia_*.log e nel riepilogo
        // ant2_energia_riepilogo_*.txt.
        bool energyCheckEnabled = default(true);
        double energyCheckWindow @unit(s) = default(30s);   // finestra W per il calo minimo
        double maxNetworkDelay @unit(s) = default(3s);      // ritardo massimo di rete D (misurato: max 2,3 s)
        double measureMaxInterval @unit(s) = default(3s);   // intervallo massimo tra due misure
        double energyCheckTolerance = default(0.01);        // tolleranza in punti percentuali
        bool energyCheckLogAll = default(false);            // registra anche i controlli superati
        // Controllo sull'energia iniziale: richiede che chi controlla conosca a
        // priori la batteria di partenza dei droni. Disattivato, perche' la GCS
        // non ha quel dato: ottiene il primo campione con il primo giro di
        // tracce. Si puo' riattivare per riprodurre il comportamento precedente.
        bool energyCheckUseInitialCapacity = default(false);
        // Calo minimo dell'energia: oltre all'ascolto si pretende il consumo dei
        // messaggi che il protocollo impone al nodo (due FANT propri ogni
        // helloInterval, piu' una ritrasmissione e un BANT per ogni generazione
        // altrui). La durata in aria si ricava dalla dimensione reale dei
        // messaggi e dalla velocita' della radio dei droni (54 Mbps, costante in
        // Ant2EnergyCheck.h). Il coefficiente riduce la parte di traffico per
        // non accusare un nodo che ha perso un FANT per una collisione:
        // 0 = solo ascolto (comportamento precedente), 1 = traffico intero.
        // Con 18 nodi e una finestra di 30 s: 2,000% con 0, 2,017% con 0,5,
        // 2,033% con 1, contro un consumo onesto misurato di 2,12-2,18%.
        double energyMinTrafficMargin = default(0.5);
        // Eta' massima del timbro in una voce di traccia: la voce viene scritta
        // dal nodo nell'istante in cui attraversa la traccia, quindi basta
        // l'intervallo massimo fra due misure piu' una tolleranza, senza il
        // ritardo di rete che serve invece ai BANT.
        double energyTraceMaxAge @unit(s) = default(3.5s);

        // --- Regola 2 della metrica di trust: controllo sulla posizione ---
        // Ogni nodo annota i REQ che riceve in un registro di eventi: un
        // reclutamento se mittente e destinatario del REQ sono diversi, un
        // avviso di batteria scarica se coincidono. Quando un BANT dichiara una
        // posizione diversa dalla precedente, lo spostamento deve essere
        // giustificato da un evento compatibile nel tempo e la destinazione
        // deve essere quella prevista. Un drone fermo non produce nessun esito.
        bool positionCheckEnabled = default(true);
        bool positionCheckLogAll = default(false);   // registra anche superati e non applicabili
        // Tolleranza sulla destinazione prevista.
        double positionCheckTolerance @unit(m) = default(10m);
        // Sotto questa distanza il drone e' considerato fermo.
        double positionStillTolerance @unit(m) = default(1m);
        // Eta' oltre la quale un evento non puo' piu' giustificare uno spostamento.
        double positionEventMaxAge @unit(s) = default(30s);
        // Spostamento di reclutamento. Sono gli stessi valori che usa moveUav():
        //   x = recruitOffset + px + r*cos(a),  y = recruitOffset + py + r*sin(a),
        //   z = recruitAltitude,  con r casuale fra 0 e recruitRadius.
        // La destinazione cade quindi dentro una sfera di raggio recruitRadius
        // centrata in (px + offset, py + offset, quota), e il controllo verifica
        // proprio questo: un intervallo di distanza da chi ha chiesto aiuto
        // lascerebbe passare uno spostamento nella direzione opposta.
        double recruitOffset @unit(m) = default(100m);
        double recruitRadius @unit(m) = default(100m);
        double recruitAltitude @unit(m) = default(50m);
        // Ritardo fra la ricezione del REQ di reclutamento e lo spostamento.
        double recruitMoveDelay @unit(s) = default(1s);

        // Attacchi per provare la regola 2.
        // Il drone accetta il reclutamento ma si sposta nella direzione opposta
        // a quella prevista: la distanza da chi ha chiesto aiuto resta
        // plausibile, ma la destinazione e' fuori dalla sfera.
        bool attackWrongRecruitMove = default(false);
        // Dal secondo attackFakePositionStart il drone dichiara la propria
        // posizione spostata di attackFakePositionOffset lungo x. Chi controlla
        // vede uno spostamento che nessun evento giustifica.
        bool attackFakePosition = default(false);
        double attackFakePositionOffset @unit(m) = default(300m);
        double attackFakePositionStart @unit(s) = default(40s);
        // La posizione falsa viene dichiarata solo nei BANT, che sono quelli che
        // decidono il reclutamento, mentre nelle voci di traccia il drone
        // dichiara quella vera: lo coglie il controllo sulla coerenza della
        // posizione a parita' di timbro.
        bool attackFakePositionOnlyBant = default(false);

        // --- Regola 3 della metrica di trust: controllo sulla disponibilita' ---
        // Lo stato atteso del drone (disponibile, impegnato, in ricarica) non
        // viene stabilito dall'arrivo del REQ, che puo' non essere giunto al
        // drone, ma dallo spostamento confermato dalla regola 2: e' quello a
        // provare che il drone ha ricevuto la richiesta e l'ha accettata. Per
        // questo non serve nessun margine temporale: la disponibilita' viene
        // messa a falsa prima dello spostamento, o nello stesso istante nel caso
        // della ricarica, mentre il valore che viaggia in un BANT viene letto
        // quando il BANT viene costruito, cioe' nell'istante del timbro o dopo.
        bool availabilityCheckEnabled = default(true);
        bool availabilityCheckLogAll = default(false);
        // Attacco: il drone dichiara sempre disponibilita' vera, anche dopo
        // essere stato reclutato, cosi' partecipa a tutti i reclutamenti e
        // lascia senza aiuto i droni in difficolta'.
        bool attackFalseAvailability = default(false);

        // --- Regola 4 della metrica di trust: controllo sul falso aiuto ---
        // Verifica un comportamento e non un valore: il drone che ha vinto il
        // reclutamento e' andato davvero a prestare aiuto? Si appoggia al
        // registro dei REQ della regola 2 e alla conferma dello spostamento
        // della regola 2 stessa, quindi non aggiunge nessun dato alla rete e non
        // rifa' la verifica geometrica, che resta una sola.
        // L'istante limite oltre il quale il comportamento deve essere visibile
        // e' t_R + maxNetworkDelay + recruitMoveDelay, dove t_R e' l'istante in
        // cui chi controlla ha ricevuto il REQ.
        bool helpCheckEnabled = default(true);
        bool helpCheckLogAll = default(false);
        // Oltre questa attesa, se non e' arrivato nessun BANT utile del
        // vincitore, la verifica viene abbandonata e contata a parte.
        double helpCheckMaxWait @unit(s) = default(60s);
        // Attacchi per provare la regola 4.
        // Il drone accetta il reclutamento, quindi si dichiara non disponibile
        // come farebbe un drone onesto, ma non si sposta.
        bool attackFalseHelp = default(false);
        // Il drone ignora del tutto i REQ a lui destinati: non accetta, non
        // cambia disponibilita' e non si sposta.
        bool attackIgnoreRecruit = default(false);

        // --- Regola 5 della metrica di trust: controllo sulla banda massima ---
        // La banda massima di un drone (max_band) viene letta all'avvio e non
        // cambia mai, quindi un drone onesto dichiara sempre lo stesso valore.
        // Due controlli: che il valore dichiarato non cambi, e che la richiesta
        // d'aiuto sia coerente con i valori dichiarati, cioe' che il throughput
        // raggiunga l'85% della banda massima dichiarata oppure che l'energia
        // sia sotto la soglia. Il secondo coglie anche chi mente sempre allo
        // stesso modo, perche' dichiarando una banda massima piu' alta del vero
        // alza la propria soglia e si contraddice quando chiede aiuto.
        bool bandCheckEnabled = default(true);
        bool bandCheckLogAll = default(false);

        // --- Regola 6 della metrica di trust: il numero di hop dichiarato ---
        // Gli hop dichiarati entrano nel punteggio di reclutamento come 1/H, ma
        // soprattutto nel feromone dell'instradamento come 100/hop: un nodo che
        // ne dichiara meno del vero diventa il prossimo salto preferito per il
        // traffico altrui, cioe' costruisce un sinkhole.
        // Il controllo locale e' certo e a costo zero: chi trasmette un
        // messaggio creato da un altro deve dichiarare almeno 2 hop. Quello
        // sulle tracce e' della sola GCS, e attribuisce la colpa per accumulo.
        bool hopCheckEnabled = default(true);
        // Di norma ogni GCS traccia solo il proprio cluster, e i bersagli sono
        // quasi tutti a un hop: le catene risultano lunghe una voce sola e il
        // controllo sulla catena degli hop non ha nulla da confrontare. Con
        // questo parametro si tracciano anche i nodi degli altri cluster, che
        // sono a piu' salti. Costa traffico: serve a misurare, non e' il modo
        // normale di far funzionare la rete.
        bool traceAllClusters = default(false);
        bool hopCheckLogAll = default(false);
        // Quante coppie sospette servono prima di accusare un nodo con il
        // controllo sulle tracce, e quale frazione delle catene attraversate
        // deve essere sospetta. Servono a distinguere il colpevole dal nodo che
        // gli sta accanto, che finisce nelle coppie solo per caso.
        int hopMinCoppieSospette = default(5);
        double hopSogliaRapporto = default(0.5);
        // Quanti VICINI DIVERSI devono essere coinvolti nelle coppie sospette
        // prima di accusare. E' la condizione che distingue il colpevole dalla
        // vittima: chi non incrementa rovina il conteggio di piu' vicini
        // diversi, mentre la sua vittima compare sempre accanto a lui solo.
        // Senza questa condizione venivano accusati anche i due vicini
        // dell'attaccante, che avevano un rapporto quasi identico al suo.
        int hopMinPartnerDistinti = default(2);

        // --- Regola 0 della metrica di trust: coerenza fra canali ---
        // Un attaccante puo' dichiarare una cosa ai droni vicini e un'altra alla
        // GCS: e' l'equivocazione, l'unica classe di attacco che nessuna delle
        // cinque regole puo' cogliere, perche' tutte guardano un canale solo.
        // La GCS raccoglie le stesse letture su due canali, le voci di traccia e
        // i BANT che riceve, e pubblica nel proprio cluster un bollettino con
        // l'IMPRONTA crittografica di ciascuna lettura (8 byte invece dei 148 di
        // un record completo). Ogni drone confronta quell'impronta con quella
        // della stessa lettura arrivata a lui: se non coincidono, la violazione
        // e' certa. Se coincidono, l'attaccante ha mentito allo stesso modo a
        // tutti, e tocca alle cinque regole coglierlo.
        bool digestCheckEnabled = default(true);
        bool digestCheckLogAll = default(false);
        // true solo per le GCS: pubblicano il bollettino nel proprio cluster.
        bool digestPublish = default(false);
        // Pubblica ogni N giri di traccia. Il contorno del pacchetto pesa piu'
        // delle righe, quindi accorpare due giri costa meno che mandarne due.
        int digestEveryRounds = default(1);
        // Letture per nodo in ogni bollettino. Tre e' il valore scelto: ogni
        // impronta viene cosi' pubblicata in tre bollettini consecutivi, e per
        // perdere un controllo bisogna perderne tre di fila. Serve perche' il
        // bollettino viaggia nel canale del cluster, che e' quello congestionato.
        // Quattro letture per nodo: con una lettura al secondo e un bollettino
        // ogni tre, quattro righe bastano a pubblicarle tutte. Il pacchetto che
        // ne risulta e' sostenibile solo grazie all'unicast, che il livello MAC
        // ritrasmette; in broadcast puro sarebbe andato perso. Misurato: la
        // copertura passa dal 68% al 76%.
        int digestMeasuresPerNode = default(4);
        int digestCopies = default(2);
        // Numero massimo di righe in un bollettino. Serve a restare sotto l'MTU:
        // un bollettino piu' grande verrebbe frammentato dal livello IP, e in
        // broadcast, senza riscontri, basta perdere un frammento per perdere
        // tutto il pacchetto. Le righe in eccesso escono nei bollettini
        // successivi, a rotazione.
        int digestMaxRows = default(28);
        // Il bollettino va a due velocita'. A ogni giro porta tutte le letture
        // dei nodi del PROPRIO cluster, che sono i destinatari del messaggio e i
        // vicini da cui essi ricevono i BANT: sono poche righe e non ruotano,
        // quindi ogni lettura viene pubblicata subito invece che una volta ogni
        // cinque bollettini. Ogni digestFullEveryRounds giri aggiunge, nello
        // spazio che resta, le letture degli altri cluster, a rotazione.
        // Spegnerlo riporta al comportamento precedente, con tutte le righe in
        // un'unica riserva a rotazione: serve a confrontare le due pubblicazioni.
        bool digestClusterFirst = default(true);
        // Il bollettino viaggiava solo in broadcast, che in 802.11 non ha ne'
        // riscontro ne' ritrasmissione. Acceso, viene mandato in UNICAST a ogni
        // vicino del cluster sentito di recente e in portata, dove il livello MAC
        // riscontra e ritrasmette, piu' una copia in broadcast per gli altri. E'
        // la stessa scelta gia' fatta per le tracce (traceUnicastMaxDistance).
        bool digestUnicast = default(true);
        // Il tetto del proprio cluster e' calibrato perche' il bollettino
        // ordinario resti della dimensione che si e' misurata consegnabile: le
        // misure mostrano che su questo canale la consegna domina tutto, perche'
        // portando il bollettino da 428 a 642 byte le ricezioni si sono quasi
        // dimezzate (da 107 a 59) e i controlli sono scesi invece di salire. Si
        // tiene quindi la stessa dimensione e si cambia solo la composizione:
        // dodici righe, tutte del proprio cluster e pubblicate a ogni giro, al
        // posto di dodici righe estratte a rotazione da cinquantasette.
        int digestMaxRowsCluster = default(24);
        int digestFullEveryRounds = default(5);
        // Tetto alle righe di REQ in un bollettino: 44 byte a riga, pesano piu'
        // delle impronte. Le altre escono nei bollettini successivi. Il registro
        // pubblicato deve risalire abbastanza indietro da coprire i dubbi in
        // attesa della regola 2: con reclutamenti ogni quindici secondi e
        // bollettini ogni uno-cinque, otto righe coprono oltre un minuto.
        int digestMaxReqRows = default(4);
        // Includi nel bollettino il registro dei REQ osservati dalla GCS: e' cio'
        // che trasforma in certezze i dubbi delle regole 2 e 4.
        bool digestIncludeReq = default(true);
        // Ogni nodo ritrasmette il bollettino una volta sola, altrimenti i droni
        // fuori portata radio dalla GCS non lo riceverebbero mai. Spegnerlo
        // riduce il traffico sul canale del cluster ma riduce la copertura.
        bool digestRelay = default(true);
        // Effetto della metrica di trust sul reclutamento. SPENTO di default:
        // un falso positivo non costerebbe un avviso nel registro, costerebbe
        // prestazioni alla rete, perche' il reclutamento e' cio' che la tiene in
        // piedi. Acceso, un drone su cui chi sceglie ha osservato almeno una
        // violazione certa non entra fra i candidati. Serve a misurare la rete
        // con e senza punizione a parita' di tutto il resto.
        bool trustPunishEnabled = default(false);
        // Soglia di energia sotto la quale il drone chiede aiuto comunque. La
        // legge sia il controllo periodico che decide di chiedere aiuto sia il
        // secondo controllo di questa regola, cosi' i due non divergono.
        double helpRequestEnergyThreshold = default(15);
        // Istante da cui attackFalseMetrics comincia a mentire: prima di quello
        // il drone dichiara i valori veri. Serve a provare i controlli che
        // confrontano una dichiarazione con quelle precedenti, per esempio
        // quello sulla banda massima che non deve cambiare.
        double attackStart @unit(s) = default(0s);

        // Registrazione traffico/consumo (solo misura, nessun effetto sul
        // protocollo): file ant2_traffico_energia_*.log con, per ogni misura di
        // ogni nodo, energia realmente consumata, frame e byte trasmessi e
        // ricevuti, tempi della radio in trasmissione/ricezione/canale occupato.
        bool trafficEnergyLog = default(false);

        // Traceroute delle GCS (snapshot della rete, vedi Ant2Trace.cc). Con
        // traceEnabled = true (da impostare solo per le GCS) il nodo lancia,
        // a intervalli casuali tra traceIntervalMin e traceIntervalMax (contati
        // dalla chiusura del giro precedente), un giro
        // di tracce verso tutti i nodi della sua tabella di stato. Ogni traccia
        // segue le tabelle di routing; ogni nodo attraversato aggiunge una voce
        // (cifrata e firmata) con i parametri che dichiara nei BANT. Lo snapshot
        // viene scritto in ant2_snapshot_<...>.log. Tutti i nodi inoltrano le
        // tracce, qualunque sia il valore di traceEnabled.
        bool traceEnabled = default(false);
        double traceStartTime @unit(s) = default(6s);     // primo giro (prima le rotte non ci sono ancora)
        double traceIntervalMin @unit(s) = default(1s);   // intervallo casuale tra due giri
        double traceIntervalMax @unit(s) = default(5s);
        double traceTimeout @unit(s) = default(2s);       // attesa delle risposte di un giro
        double traceStagger @unit(s) = default(0.02s);    // distanza tra due tracce dello stesso giro
        double traceRetryDelay @unit(s) = default(1s);    // secondo tentativo per le tracce senza risposta
        // Modo di trasmissione di ogni passaggio della traccia. Verso un vicino
        // la cui distanza (dalla tabella di stato, cioe' dalle posizioni
        // dichiarate nei BANT) e' nota e non supera traceUnicastMaxDistance,
        // la traccia va in UNICAST: il livello MAC conferma e ritrasmette.
        // Verso un vicino piu' lontano (il satellite, a ~100 km) o di cui non
        // si conosce la distanza, va in BROADCAST, ripetuta traceBroadcastCopies
        // volte: a quella distanza la conferma (ACK) arriverebbe dopo la
        // scadenza del suo timeout, e l'unicast produrrebbe solo ritrasmissioni
        // a vuoto e code piene (osservato nella prova con il solo unicast).
        double traceUnicastMaxDistance @unit(m) = default(2000m);
        int traceBroadcastCopies = default(2);
        // Vicini riportati nelle voci delle tracce: quelli sentiti negli
        // ultimi traceNeighborTimeout secondi (al massimo 12).
        double traceNeighborTimeout @unit(s) = default(10s);
        // NB: con legacyEnergy = false il REQ contiene anche il cluster di chi
        // chiede aiuto (4 byte): il drone reclutato passa a quel cluster.
        // Snapshot per cluster: ogni GCS traccia solo i droni del proprio
        // cluster e, a ogni chiusura di giro, invia il proprio snapshot alle
        // altre GCS. snapshotRelay = true per GCS e satellite: inoltrano gli
        // snapshot (una volta ciascuno, in broadcast, snapshotCopies copie).
        bool snapshotRelay = default(false);
        int snapshotCopies = default(2);
        int traceMaxHops = default(10);                   // passaggi massimi di una traccia

        // Added to identify each UAV
        int name = default(100);
        
        // Added to compute the bandwidth usage
        double max_band = default(0.0);
        
        // Added to identify the parent cluster ID of each UAV
        int cluster_id;

        // Added for security (Ascon-AEAD128 + Ed25519): percorsi dei file di
        // provisioning OFFLINE, generati con gli strumenti in tools/ prima
        // della missione. Usati solo se useCentralAuthority = false.
        // NB: default("") obbligatorio, altrimenti OMNeT++ pretende un valore per
        // ogni nodo anche quando si usa l'autorita' centrale e questi file non
        // servono affatto (errore "Enter parameter ... (unassigned)").
        // Se si usa il provisioning offline e ci si dimentica di valorizzarli,
        // il caricamento fallisce comunque con un errore esplicito: il nodo non
        // parte mai "silenziosamente insicuro".
        string groupKeyFile = default("");      // chiave simmetrica di gruppo (16 byte), uguale per tutta la flotta
        string ownPubKeyFile = default("");     // chiave pubblica Ed25519 di QUESTO nodo (32 byte)
        string ownPrivKeyFile = default("");    // chiave privata Ed25519 di QUESTO nodo (64 byte) - MAI condivisa
        string fleetRosterFile = default("");   // tabella indirizzo -> chiave pubblica di tutta la flotta

        // APPROCCIO ALTERNATIVO: autorita' centrale "in-simulazione" (vedi
        // Ant2KeyAuthority). Se true, i quattro parametri sopra vengono ignorati
        // e le chiavi si ottengono chiamando il modulo Ant2KeyAuthority presente
        // al livello top della rete, con questo nome.
        bool useCentralAuthority = default(false);
        string keyAuthorityName = default("keyAuthority");

        // SOLO PER I TEST: se true, questo nodo si comporta da attaccante.
        // Firma i propri messaggi con una chiave NON riconosciuta dagli altri
        // nodi, simulando un drone compromesso che tenta di iniettare
        // messaggi di routing falsi. Serve a dimostrare che la verifica
        // crittografica discrimina davvero (test negativo).
        // Interruttore generale del livello di sicurezza. Con false il protocollo
        // si comporta esattamente come prima delle modifiche: nessuna firma,
        // nessuna cifratura, e messaggi delle DIMENSIONI ORIGINALI (128 bit).
        // Serve per ottenere un baseline pulito nelle misure di overhead:
        // stesso identico codice, unica variabile la presenza della sicurezza.
        bool securityEnabled = default(true);

        // Algoritmo AEAD usato per confidenzialita' + integrita' del payload.
        // Valori ammessi (devono essere UGUALI per tutti i nodi della rete):
        //   "ascon128"          Ascon-AEAD128, NIST SP 800-232 (chiave 16 B, nonce 16 B)
        //   "aes128gcm"         AES-128-GCM,   FIPS 197 + SP 800-38D (chiave 16 B, nonce 12 B)
        //   "aes192gcm"         AES-192-GCM                    (chiave 24 B, nonce 12 B)
        //   "aes256gcm"         AES-256-GCM                    (chiave 32 B, nonce 12 B)
        //   "chacha20poly1305"  ChaCha20-Poly1305, RFC 8439    (chiave 32 B, nonce 12 B)
        //   "xoodyak"           Xoodyak, finalista NIST LWC    (chiave 16 B, nonce 16 B, tag 16 B)
        //   "tinyjambu128"      TinyJAMBU-128 (v2), finalista NIST LWC
        //                                                      (chiave 16 B, nonce 12 B, tag  8 B)
        // Tutti producono un ciphertext della stessa lunghezza del plaintext.
        // I primi sei hanno un tag da 16 byte: con loro la DIMENSIONE DEI
        // PACCHETTI NON CAMBIA (BANT 153 B, REQ 121 B, FANT 80 B), quindi le
        // differenze riguardano solo il costo computazionale.
        // ECCEZIONE: TinyJAMBU-128 ha un tag da 8 byte, quindi BANT e REQ sono
        // 8 byte piu' corti (BANT 145 B, REQ 113 B; il FANT, solo firmato, resta 80 B).
        // Xoodyak e TinyJAMBU-128 usano i primi 16 byte della chiave di gruppo,
        // esattamente come Ascon.
        string aeadAlgorithm = default("ascon128");

        // Diario dello scenario (Ant2Scenario.cc): scrive nella cartella dei
        // risultati il file ant2_scenario_<config>_rN.log, con la cronologia di
        // ogni drone (avvio, FANT e BANT ricevuti, richieste d'aiuto,
        // reclutamenti, spostamenti, soglie di energia, ricarica, spegnimento) e
        // un riepilogo finale. Solo osservazione: con true o false i risultati
        // della simulazione sono identici. Per disattivarlo:
        //   **.routing.scenarioLog = false
        bool scenarioLog = default(true);

        // Algoritmo di firma digitale usato per l'autenticazione dell'origine.
        // Valori ammessi (uguali per tutti i nodi):
        //   "ed25519"    Ed25519, RFC 8032 (pubblica 32 B, privata 64 B)
        //   "ecdsap256"  ECDSA su curva P-256 con SHA-256, FIPS 186-4
        //                (pubblica 64 B, privata 32 B)
        // La firma e' di 64 byte con entrambi: la DIMENSIONE DEI PACCHETTI NON
        // CAMBIA, quindi anche qui la differenza e' solo computazionale.
        string signatureAlgorithm = default("ed25519");

        bool isAttacker = default(false);

        // --- ATTACCHI NON RILEVABILI DAL LIVELLO CRITTOGRAFICO (solo per i test) ---
        // Modellano un nodo LEGITTIMO, in possesso di chiavi valide, che abusa
        // della propria posizione nel protocollo. Firma e cifratura restano
        // corrette: e' il CONTENUTO a essere falso. Servono a motivare la
        // necessita' di una metrica di trust, che opera dove la crittografia
        // non puo' arrivare.

        // Dichiara nei propri BANT valori di energia e banda disponibile
        // artificiosamente favorevoli, per vincere sempre la selezione del
        // recruiting. I dati viaggiano cifrati e firmati correttamente.
        bool attackFalseMetrics = default(false);

        // Non incrementa hopdistance quando inoltra: i nodi a valle credono
        // che il mittente sia adiacente. Sfrutta il fatto che hopdistance e'
        // un campo in chiaro non coperto dalla firma.
        bool attackHopDistance = default(false);

        // Se true, ogni singolo evento di sicurezza viene stampato anche in
        // console. Di default false: il dettaglio completo finisce comunque
        // sempre nel file ant2_security_events.log, mentre la console resta
        // leggibile (banner iniziale, avvio dei nodi, riepilogo finale).
        bool securityConsoleVerbose = default(false);
        
        // Added for energy monitoring
	    @signal[arrival](type="long");
        @statistic[energy](title="energy"; source="arrival"; record=vector,stats; interpolationmode=none);
        @signal[arrival1](type="int");
        @statistic[totalMantPkts](title="totalPacketsManet"; source="arrival1"; record=last,vector);
        @signal[arrival2](type="int");
        @statistic[totalReqPkts](title="totalPacketsReq"; source="arrival2"; record=last,vector);
        @signal[arrival3](type="int");
        @statistic[energyNode](title="energyNode"; source="arrival3"; record=last,vector);  
              
    gates:
        input ipIn;
        output ipOut;
}
