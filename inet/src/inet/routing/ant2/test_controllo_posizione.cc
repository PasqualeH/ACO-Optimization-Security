//
// test_controllo_posizione.cc
//
// Test automatici della regola 2 della metrica di trust (controllo sulla
// posizione dichiarata nei BANT). Verificano la logica pura di
// Ant2PositionCheck.h, senza OMNeT++ e senza INET.
//
// Compilazione ed esecuzione, dalla cartella radice del progetto:
//   g++ -std=c++17 -DANT2_TEST_STANDALONE -I inet/src \
//       inet/src/inet/routing/ant2/test_controllo_posizione.cc -o test_controllo_posizione
//   ./test_controllo_posizione
//
// Il corpo e' racchiuso in ANT2_TEST_STANDALONE perche' il makefile di INET
// compila tutti i .cc sotto src dentro libINET: senza questa protezione il main()
// di questo file finirebbe nella libreria e il collegamento fallirebbe.
#ifdef ANT2_TEST_STANDALONE

#include <cstdio>
#include <cstdlib>
#include <cmath>

#include "inet/routing/ant2/Ant2PositionCheck.h"

using namespace ant2position;

static int eseguiti = 0, falliti = 0;

static void verifica(bool condizione, const char *descrizione)
{
    eseguiti++;
    if (condizione)
        std::printf("[ OK ] %s\n", descrizione);
    else {
        falliti++;
        std::printf("[FAIL] %s\n", descrizione);
    }
}

static const char *nomeEsito(Esito e)
{
    switch (e) {
        case Esito::SUPERATO: return "SUPERATO";
        case Esito::VIOLATO: return "VIOLATO";
        case Esito::DUBBIO: return "DUBBIO";
        default: return "NON_APPLICABILE";
    }
}

static void stampa(const std::vector<PositionOutcome>& r)
{
    for (auto& o : r)
        std::printf("        %s  %s  %s\n", o.controllo.c_str(), nomeEsito(o.esito), o.dettaglio.c_str());
}

static Esito esitoDi(const std::vector<PositionOutcome>& r, const char *controllo)
{
    for (auto& o : r)
        if (o.controllo == controllo)
            return o.esito;
    return Esito::NON_APPLICABILE;
}

static bool vuoto(const std::vector<PositionOutcome>& r) { return r.empty(); }

static PositionSample S(double t, Vec3 pos, double energia = -1, const char *fonte = "BANT")
{
    PositionSample s;
    s.t = t; s.pos = pos; s.energia = energia; s.fonte = fonte;
    return s;
}

static MoveEvent reclutamento(uint32_t drone, Vec3 posRichiedente, double istante, unsigned int seq = 1)
{
    MoveEvent e;
    e.tipo = TipoEvento::RECLUTAMENTO; e.drone = drone;
    e.posRichiedente = posRichiedente; e.istante = istante; e.seq = seq;
    return e;
}

static MoveEvent avviso(uint32_t drone, double istante, unsigned int seq = 1)
{
    MoveEvent e;
    e.tipo = TipoEvento::AVVISO; e.drone = drone; e.istante = istante; e.seq = seq;
    return e;
}

int main()
{
    // Parametri del progetto: offset e raggio di moveUav(), quota 50, ritardo
    // dello spostamento 1 s, partenza per la stazione 1 s dopo l'avviso,
    // stazione in (1000, 1000, 50), ritardo massimo di rete 3 s.
    PositionCheckParams p;
    p.maxNetworkDelay = 3.0;
    const uint32_t X = 7;                 // drone osservato
    const Vec3 richiedente(300, 400, 50); // chi ha chiesto aiuto
    const Vec3 bersaglio = p.bersaglioReclutamento(richiedente);  // (400, 500, 50)
    const Vec3 lontano(800, 200, 50);     // posizione iniziale del drone osservato

    std::printf("Parametri: offset %.0f m, raggio %.0f m, quota %.0f m, ritardo mossa %.0f s, D %.0f s\n",
                p.recruitOffset, p.recruitRadius, p.recruitAltitude, p.recruitMoveDelay, p.maxNetworkDelay);
    std::printf("Chi chiede aiuto in (300, 400, 50) -> centro previsto %s\n\n",
                detail::fmtPos(bersaglio).c_str());

    std::printf("== Casi di base ==\n");
    {
        PositionObservedState st;
        std::vector<MoveEvent> reg;
        auto r = checkPosition(st, S(10.0, lontano), p, reg, X);
        verifica(esitoDi(r, "posizione") == Esito::NON_APPLICABILE,
                 "prima misura: diventa il riferimento, niente da confrontare");

        r = checkPosition(st, S(10.0, lontano), p, reg, X);
        verifica(esitoDi(r, "posizione") == Esito::NON_APPLICABILE, "stesso timbro: misura ripetuta");

        r = checkPosition(st, S(8.0, lontano), p, reg, X);
        verifica(esitoDi(r, "posizione") == Esito::NON_APPLICABILE, "timbro piu' vecchio: arrivata in disordine");

        r = checkPosition(st, S(13.0, Vec3(800.3, 200.2, 50)), p, reg, X);
        verifica(esitoDi(r, "posizione") == Esito::SUPERATO,
                 "drone fermo al riferimento (scostamento 0,4 m sotto la tolleranza): SUPERATO");
    }

    std::printf("\n== Reclutamento ==\n");
    {
        // REQ di reclutamento ricevuto a 12 s, spostamento previsto a 13 s.
        PositionObservedState st;
        std::vector<MoveEvent> reg{reclutamento(X, richiedente, 12.0)};
        checkPosition(st, S(10.0, lontano), p, reg, X);
        auto r = checkPosition(st, S(14.0, Vec3(430, 540, 50)), p, reg, X); stampa(r);
        verifica(esitoDi(r, "posizione") == Esito::SUPERATO,
                 "destinazione a 50 m dal centro previsto: SUPERATO");
        verifica(reg[0].usato, "l'evento di reclutamento viene consumato");

        // Lo stesso evento non puo' giustificare un secondo spostamento.
        r = checkPosition(st, S(17.0, Vec3(700, 700, 50)), p, reg, X); stampa(r);
        verifica(esitoDi(r, "posizione") == Esito::DUBBIO,
                 "secondo spostamento con l'evento gia' consumato: DUBBIO");
    }
    {
        // Destinazione sbagliata: distanza plausibile da chi ha chiesto aiuto,
        // ma nella direzione opposta. Con il controllo a intervallo di distanza
        // (fra 40 e 250 m) questo passerebbe; con la sfera no.
        PositionObservedState st;
        std::vector<MoveEvent> reg{reclutamento(X, richiedente, 12.0)};
        checkPosition(st, S(10.0, lontano), p, reg, X);
        Vec3 opposta(richiedente.x - 106, richiedente.y - 106, 50);   // 150 m a sud-ovest
        double dalRichiedente = distanza(opposta, richiedente);
        auto r = checkPosition(st, S(14.0, opposta), p, reg, X); stampa(r);
        std::printf("        distanza da chi ha chiesto aiuto: %.1f m (dentro l'intervallo 40-250 m)\n", dalRichiedente);
        verifica(dalRichiedente > 40 && dalRichiedente < 250, "la destinazione falsa dista 150 m, plausibile come intervallo");
        verifica(esitoDi(r, "posizione") == Esito::VIOLATO,
                 "destinazione nella direzione opposta: VIOLATO (la sfera la coglie, l'intervallo no)");
        verifica(!reg[0].usato, "un evento che non giustifica lo spostamento non viene consumato");
    }
    {
        // Quota sbagliata: moveUav() porta sempre a quota 50.
        PositionObservedState st;
        std::vector<MoveEvent> reg{reclutamento(X, richiedente, 12.0)};
        checkPosition(st, S(10.0, lontano), p, reg, X);
        auto r = checkPosition(st, S(14.0, Vec3(400, 500, 300)), p, reg, X); stampa(r);
        verifica(esitoDi(r, "posizione") == Esito::VIOLATO,
                 "destinazione giusta su x e y ma a quota 300 m: VIOLATO");
    }
    {
        // Evento fuori finestra: il REQ e' arrivato troppo presto perche' lo
        // spostamento cada fra le due misure.
        PositionObservedState st;
        std::vector<MoveEvent> reg{reclutamento(X, richiedente, 1.0)};
        checkPosition(st, S(10.0, lontano), p, reg, X);
        auto r = checkPosition(st, S(14.0, Vec3(430, 540, 50)), p, reg, X); stampa(r);
        verifica(esitoDi(r, "posizione") == Esito::DUBBIO,
                 "REQ troppo vecchio perche' lo spostamento cada fra le due misure: DUBBIO");
    }
    {
        // Spostamento senza nessun evento osservato.
        PositionObservedState st;
        std::vector<MoveEvent> reg;
        checkPosition(st, S(10.0, lontano), p, reg, X);
        auto r = checkPosition(st, S(14.0, Vec3(430, 540, 50)), p, reg, X); stampa(r);
        verifica(esitoDi(r, "posizione") == Esito::DUBBIO,
                 "spostamento senza nessun evento: DUBBIO, non violazione certa");
    }

    std::printf("\n== Due REQ compatibili per lo stesso drone (il caso di adh[11]) ==\n");
    {
        // Caso visto nella simulazione TestPosizioneOnesta: adh[11] accetta la
        // richiesta di adh[4] a 27,938 s e si sposta a 28,938 s; a 28,993 s
        // arriva la richiesta di adh[8], che adh[11] RIFIUTA perche' non e' piu'
        // disponibile, limitandosi a inoltrarla. Fra le due misure chi controlla
        // vede quindi due REQ compatibili, e lo spostamento e' giustificato dal
        // primo. Prendendo l'evento piu' recente si bocciava un drone onesto.
        const Vec3 primoRichiedente(450, 650, 50);    // adh[4]
        const Vec3 secondoRichiedente(272, 759.2, 50);  // adh[8]
        const Vec3 partenza(1800, 500, 50);
        const Vec3 destinazione(527.4, 722.7, 50);
        PositionObservedState st;
        std::vector<MoveEvent> reg{reclutamento(X, primoRichiedente, 27.938, 1),
                                   reclutamento(X, secondoRichiedente, 28.993, 2)};
        checkPosition(st, S(26.410, partenza), p, reg, X);
        auto r = checkPosition(st, S(29.295, destinazione), p, reg, X); stampa(r);
        verifica(esitoDi(r, "posizione") == Esito::SUPERATO,
                 "due REQ compatibili, spostamento verso il primo: SUPERATO");
        verifica(reg[0].usato && !reg[1].usato,
                 "viene consumato il REQ che spiega lo spostamento, non l'altro");

        // Se invece nessuno dei due lo spiega, resta una violazione certa.
        PositionObservedState st2;
        std::vector<MoveEvent> reg2{reclutamento(X, primoRichiedente, 27.938, 1),
                                    reclutamento(X, secondoRichiedente, 28.993, 2)};
        checkPosition(st2, S(26.410, partenza), p, reg2, X);
        r = checkPosition(st2, S(29.295, Vec3(100, 100, 50)), p, reg2, X); stampa(r);
        verifica(esitoDi(r, "posizione") == Esito::VIOLATO,
                 "due REQ compatibili, destinazione che nessuno spiega: VIOLATO");
    }

    std::printf("\n== Tutte le destinazioni che moveUav() puo' produrre devono passare ==\n");
    {
        // Si riproduce la formula di moveUav():
        //   x = offset + px + r*cos(a), y = offset + py + r*sin(a), z = 50
        // Griglia di 72 angoli (ogni 5 gradi, quindi anche 45 e 225) per 11
        // raggi, cosi' da toccare gli estremi esatti.
        int provati = 0, respinti = 0;
        double distMin = 1e9, distMax = 0;
        for (int ia = 0; ia < 72; ia++) {
            for (int ir = 0; ir <= 10; ir++) {
                double a = 2 * M_PI * ia / 72.0;
                double raggio = p.recruitRadius * ir / 10.0;
                Vec3 dest(p.recruitOffset + richiedente.x + raggio * std::cos(a),
                          p.recruitOffset + richiedente.y + raggio * std::sin(a),
                          p.recruitAltitude);
                double d = distanza(dest, richiedente);
                if (d < distMin) distMin = d;
                if (d > distMax) distMax = d;
                PositionObservedState st;
                std::vector<MoveEvent> reg{reclutamento(X, richiedente, 12.0)};
                checkPosition(st, S(10.0, lontano), p, reg, X);
                auto r = checkPosition(st, S(14.0, dest), p, reg, X);
                provati++;
                if (esitoDi(r, "posizione") != Esito::SUPERATO)
                    respinti++;
            }
        }
        std::printf("        %d destinazioni provate, distanza da chi chiede aiuto fra %.1f e %.1f m\n",
                    provati, distMin, distMax);
        verifica(respinti == 0, "nessuna destinazione lecita di moveUav() viene respinta");
        verifica(distMin > 41.0 && distMin < 42.0, "la distanza minima lecita e' 41,4 m");
        verifica(distMax > 241.0 && distMax < 242.0, "la distanza massima lecita e' 241,4 m");
    }

    std::printf("\n== Stazione di ricarica ==\n");
    {
        PositionObservedState st;
        std::vector<MoveEvent> reg{avviso(X, 20.0)};
        checkPosition(st, S(19.0, lontano, 14.8), p, reg, X);
        auto r = checkPosition(st, S(23.0, p.stazione, 12.0), p, reg, X); stampa(r);
        verifica(esitoDi(r, "posizione") == Esito::SUPERATO,
                 "andata alla stazione dopo l'avviso di batteria scarica: SUPERATO");
        verifica(reg[0].usato, "l'avviso viene consumato");

        // Ritorno dalla stazione nella posizione di partenza, con energia salita.
        r = checkPosition(st, S(60.0, lontano, 100.0), p, reg, X); stampa(r);
        verifica(esitoDi(r, "posizione") == Esito::SUPERATO,
                 "ritorno dalla stazione nella posizione di partenza: SUPERATO");
    }
    {
        PositionObservedState st;
        std::vector<MoveEvent> reg;
        checkPosition(st, S(19.0, lontano, 14.8), p, reg, X);
        auto r = checkPosition(st, S(23.0, p.stazione, 12.0), p, reg, X); stampa(r);
        verifica(esitoDi(r, "posizione") == Esito::DUBBIO,
                 "arrivo alla stazione senza avviso osservato: DUBBIO");
    }
    {
        // Lascia la stazione per una posizione diversa da quella di partenza.
        PositionObservedState st;
        std::vector<MoveEvent> reg{avviso(X, 20.0)};
        checkPosition(st, S(19.0, lontano, 14.8), p, reg, X);
        checkPosition(st, S(23.0, p.stazione, 12.0), p, reg, X);
        auto r = checkPosition(st, S(60.0, Vec3(200, 900, 50), 100.0), p, reg, X); stampa(r);
        verifica(esitoDi(r, "posizione") == Esito::VIOLATO,
                 "lascia la stazione per una posizione diversa dalla partenza: VIOLATO");
    }
    {
        // Chi controlla vede il drone per la prima volta quando e' gia' alla
        // stazione: non sa da dove era partito e non puo' giudicare il ritorno.
        PositionObservedState st;
        std::vector<MoveEvent> reg;
        checkPosition(st, S(23.0, p.stazione, 12.0), p, reg, X);
        auto r = checkPosition(st, S(60.0, lontano, 100.0), p, reg, X); stampa(r);
        verifica(esitoDi(r, "posizione") == Esito::NON_APPLICABILE,
                 "ritorno dalla stazione con partenza non nota a chi controlla: NON_APPLICABILE");
    }

    std::printf("\n== Reclutamento annullato perche' il drone era in ricarica ==\n");
    {
        // moveUav() esce senza spostare se il drone e' andato a ricaricarsi: il
        // reclutamento non deve restare nel registro a giustificare un
        // movimento successivo.
        std::vector<MoveEvent> reg{reclutamento(X, richiedente, 12.0)};
        consumaReclutamentiAnnullati(reg, X, true);
        verifica(reg[0].usato, "drone alla stazione: il reclutamento non eseguito viene consumato");

        std::vector<MoveEvent> reg2{reclutamento(X, richiedente, 12.0)};
        consumaReclutamentiAnnullati(reg2, X, false);
        verifica(!reg2[0].usato, "drone non alla stazione: il reclutamento resta valido");
    }

    std::printf("\n== Pulizia del registro ==\n");
    {
        std::vector<MoveEvent> reg{reclutamento(X, richiedente, 10.0), reclutamento(X, richiedente, 95.0, 2)};
        reg[1].usato = false;
        ripuliscoRegistro(reg, 100.0, 30.0);
        verifica(reg.size() == 1 && reg[0].seq == 2, "gli eventi piu' vecchi dell'eta' massima vengono scartati");

        std::vector<MoveEvent> reg2{reclutamento(X, richiedente, 95.0)};
        reg2[0].usato = true;
        ripuliscoRegistro(reg2, 100.0, 30.0);
        verifica(reg2.empty(), "gli eventi gia' consumati vengono scartati");
    }

    std::printf("\n== Coerenza della posizione (stesso timbro, posizione diversa) ==\n");
    {
        PositionObservedState st;
        std::vector<MoveEvent> reg;
        checkPosition(st, S(20.0, lontano), p, reg, X);
        auto r = checkPosition(st, S(20.0, Vec3(350, 450, 50), -1, "una voce di traccia"), p, reg, X);
        stampa(r);
        verifica(esitoDi(r, "coerenza della posizione") == Esito::VIOLATO,
                 "due posizioni diverse con lo stesso timbro, in un BANT e in una traccia: VIOLATO");

        r = checkPosition(st, S(20.0, lontano, -1, "una voce di traccia"), p, reg, X);
        verifica(vuoto(r) || esitoDi(r, "coerenza della posizione") != Esito::VIOLATO,
                 "la stessa posizione dichiarata due volte con lo stesso timbro: nessuna violazione");

        // Il confronto vale anche fra misure non consecutive.
        checkPosition(st, S(23.0, lontano), p, reg, X);
        checkPosition(st, S(26.0, lontano), p, reg, X);
        r = checkPosition(st, S(23.0, Vec3(100, 100, 50), -1, "una voce di traccia"), p, reg, X);
        verifica(esitoDi(r, "coerenza della posizione") == Esito::VIOLATO,
                 "contraddizione su un timbro di due misure prima: VIOLATO (storico dei timbri)");
    }

    std::printf("\n== Attacco: destinazione di reclutamento specchiata (attackWrongRecruitMove) ==\n");
    {
        // L'attaccante accetta il reclutamento ma si sposta nella direzione
        // opposta: stessa distanza plausibile, direzione sbagliata.
        PositionObservedState st;
        std::vector<MoveEvent> reg{reclutamento(X, richiedente, 12.0)};
        checkPosition(st, S(10.0, lontano), p, reg, X);
        Vec3 specchiata(-p.recruitOffset + richiedente.x + 30, -p.recruitOffset + richiedente.y - 40,
                        p.recruitAltitude);
        auto r = checkPosition(st, S(14.0, specchiata), p, reg, X); stampa(r);
        std::printf("        distanza da chi ha chiesto aiuto: %.1f m\n", distanza(specchiata, richiedente));
        verifica(esitoDi(r, "posizione") == Esito::VIOLATO,
                 "destinazione specchiata rispetto al centro previsto: VIOLATO");
    }

    std::printf("\n== Attacco: posizione falsa dichiarata a meta' simulazione (attackFakePosition) ==\n");
    {
        // L'attaccante dichiara la propria posizione spostata di 300 m a partire
        // da un certo istante: chi controlla vede uno spostamento che nessun
        // evento giustifica.
        PositionObservedState st;
        std::vector<MoveEvent> reg;
        checkPosition(st, S(38.0, lontano), p, reg, X);
        auto r = checkPosition(st, S(41.0, Vec3(lontano.x + 300, lontano.y, lontano.z)), p, reg, X);
        stampa(r);
        verifica(esitoDi(r, "posizione") == Esito::DUBBIO,
                 "la posizione dichiarata salta di 300 m senza nessun evento: DUBBIO");
    }

    std::printf("\n== Limite noto: una posizione falsa dichiarata da sempre non viene colta ==\n");
    {
        // Se l'attaccante dichiara la stessa posizione falsa dal primo BANT, la
        // prima misura diventa il riferimento e lui non se ne discosta mai: i
        // controlli risultano superati. E' il limite strutturale di qualunque
        // controllo che non disponga di un riferimento esterno al drone, e non si
        // risolve con piu' campioni: serve una capacita' dichiarata e firmata
        // all'arruolamento, oppure un'altra regola che misuri la stessa grandezza
        // per altra via.
        PositionObservedState st;
        std::vector<MoveEvent> reg;
        int superati = 0, altri = 0;
        double t = 0;
        for (int i = 0; i < 20; i++) {
            t += 2.5;
            for (auto& e : checkPosition(st, S(t, Vec3(350, 450, 50)), p, reg, X)) {
                if (e.esito == Esito::SUPERATO) superati++;
                else if (e.esito != Esito::NON_APPLICABILE) altri++;
            }
        }
        std::printf("        superati %d, violazioni o dubbi %d\n", superati, altri);
        verifica(superati == 19 && altri == 0,
                 "posizione falsa ma costante: tutti superati, limite da coprire con un riferimento esterno");
    }

    std::printf("\n== Drone onesto fermo per 120 s (nessun falso positivo) ==\n");
    {
        PositionObservedState st;
        std::vector<MoveEvent> reg;
        int superati = 0, sospetti = 0;
        double t = 0;
        for (int i = 0; i < 50; i++) {
            t += 2.4;
            // piccolo rumore sotto la tolleranza del fermo
            Vec3 q(lontano.x + 0.1 * ((i % 3) - 1), lontano.y + 0.1 * ((i % 5) - 2), lontano.z);
            for (auto& e : checkPosition(st, S(t, q, 90 - 0.07 * t), p, reg, X)) {
                if (e.esito == Esito::SUPERATO) superati++;
                else if (e.esito == Esito::VIOLATO || e.esito == Esito::DUBBIO) sospetti++;
            }
        }
        std::printf("        superati %d, violazioni o dubbi %d\n", superati, sospetti);
        verifica(superati == 49 && sospetti == 0,
                 "un drone fermo produce un controllo superato per ogni misura e nessun sospetto");
    }

    // ------------------------------------------------------------------
    // L'ancora: il riferimento non avanza quando il drone mente
    // ------------------------------------------------------------------
    std::printf("\n== L'ancora non avanza su una bugia: la violazione si ripete ==\n");
    {
        // Il drone e' fermo, poi al timbro 41 dichiara 300 m piu' a est e ci
        // resta. Con il confronto sulla misura precedente violerebbe una volta
        // sola; con l'ancora ogni misura successiva e' ancora confrontata con la
        // posizione vera e resta sospetta.
        PositionObservedState st;
        std::vector<MoveEvent> reg;
        checkPosition(st, S(38.0, lontano), p, reg, X);
        const Vec3 falsa(lontano.x + 300, lontano.y, lontano.z);
        int sospetti = 0;
        double t = 38;
        for (int i = 0; i < 10; i++) {
            t += 3.0;
            for (auto& e : checkPosition(st, S(t, falsa), p, reg, X))
                if (e.esito == Esito::DUBBIO || e.esito == Esito::VIOLATO)
                    sospetti++;
        }
        std::printf("        misure sospette su 10 dichiarazioni della posizione falsa: %d\n", sospetti);
        verifica(sospetti == 10, "l'ancora resta alla posizione vera: tutte le dichiarazioni false sono sospette");
        verifica(st.sospesi.size() == 10, "i dieci dubbi restano in attesa del bollettino");

        // Il drone torna alla posizione vera: la bugia e' finita e il controllo
        // torna a essere superato.
        auto r = checkPosition(st, S(t + 3.0, lontano), p, reg, X);
        verifica(esitoDi(r, "posizione") == Esito::SUPERATO,
                 "tornato alla posizione vera: SUPERATO, la punizione si ferma");
    }

    // ------------------------------------------------------------------
    // Il bollettino dei REQ della GCS decide i dubbi
    // ------------------------------------------------------------------
    std::printf("\n== Il bollettino scioglie il dubbio: il REQ esisteva ==\n");
    {
        // Il drone si sposta verso il centro previsto, ma chi controlla non ha
        // ricevuto il REQ: dubbio. Poi il bollettino della GCS porta quel REQ.
        PositionObservedState st;
        std::vector<MoveEvent> reg;
        checkPosition(st, S(10.0, lontano), p, reg, X);
        auto r = checkPosition(st, S(14.0, Vec3(430, 540, 50)), p, reg, X);
        verifica(esitoDi(r, "posizione") == Esito::DUBBIO,
                 "spostamento verso il centro previsto senza REQ osservato: DUBBIO");

        reg.push_back(reclutamento(X, richiedente, 12.0));   // arriva dal bollettino
        auto d = risolviDubbiPosizione(st, p, reg, X, 20.0, 12.0);
        stampa(d);
        verifica(esitoDi(d, "posizione") == Esito::SUPERATO,
                 "il REQ pubblicato dalla GCS giustifica lo spostamento: dubbio sciolto in SUPERATO");
        verifica(st.sospesi.empty(), "nessun dubbio resta in attesa");
        // E l'ancora e' avanzata: la posizione nuova e' ora il riferimento.
        auto r2 = checkPosition(st, S(17.0, Vec3(430, 540, 50)), p, reg, X);
        verifica(esitoDi(r2, "posizione") == Esito::SUPERATO,
                 "l'ancora e' avanzata sulla destinazione lecita");
    }

    std::printf("\n== Il bollettino condanna il dubbio: nessun REQ esisteva ==\n");
    {
        PositionObservedState st;
        std::vector<MoveEvent> reg;
        checkPosition(st, S(38.0, lontano), p, reg, X);
        auto r = checkPosition(st, S(41.0, Vec3(lontano.x + 300, lontano.y, lontano.z)), p, reg, X);
        verifica(esitoDi(r, "posizione") == Esito::DUBBIO, "salto di 300 m: DUBBIO in attesa");

        // Bollettino emesso a 45 s, registro vuoto: la GCS non conosceva nessun
        // REQ, quindi copre tutto il passato.
        auto d = risolviDubbiPosizione(st, p, reg, X, 45.0, -1e300);
        stampa(d);
        verifica(esitoDi(d, "posizione") == Esito::VIOLATO,
                 "il bollettino esclude che un REQ esistesse: violazione certa");
        verifica(st.sospesi.empty(), "il dubbio e' stato deciso");
    }

    std::printf("\n== Il bollettino non ancora arrivato lascia il dubbio in attesa ==\n");
    {
        PositionObservedState st;
        std::vector<MoveEvent> reg;
        checkPosition(st, S(38.0, lontano), p, reg, X);
        checkPosition(st, S(41.0, Vec3(lontano.x + 300, lontano.y, lontano.z)), p, reg, X);

        // Nessun bollettino ricevuto: non si condanna.
        auto d = risolviDubbiPosizione(st, p, reg, X, -1, -1e300);
        verifica(d.empty() && st.sospesi.size() == 1,
                 "senza bollettino il dubbio resta dubbio e non punisce");

        // Bollettino troppo vicino allo spostamento: dentro il margine di rete,
        // il REQ potrebbe non essere ancora arrivato alla GCS.
        d = risolviDubbiPosizione(st, p, reg, X, 42.0, -1e300);
        verifica(d.empty() && st.sospesi.size() == 1,
                 "bollettino entro il margine di rete: ancora nessuna condanna");

        // Bollettino che non risale abbastanza indietro: il REQ che giustificava
        // lo spostamento potrebbe essere stato tagliato dal tetto alle righe.
        d = risolviDubbiPosizione(st, p, reg, X, 60.0, 50.0);
        verifica(d.empty() && st.sospesi.size() == 1,
                 "registro pubblicato che non copre la finestra: nessuna condanna");

        // Bollettino che copre la finestra: adesso si condanna.
        d = risolviDubbiPosizione(st, p, reg, X, 60.0, 20.0);
        verifica(esitoDi(d, "posizione") == Esito::VIOLATO,
                 "registro che copre la finestra: violazione certa");
    }

    std::printf("\n%d test eseguiti, %d falliti\n", eseguiti, falliti);
    return falliti == 0 ? 0 : 1;
}

#endif // ANT2_TEST_STANDALONE
