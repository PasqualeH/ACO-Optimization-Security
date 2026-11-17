//
// test_controllo_hop.cc
//
// Test automatici della regola 6 della metrica di trust (hop dichiarati).
// Verificano la logica pura di Ant2HopCheck.h, senza OMNeT++ e senza INET.
//
// Compilazione ed esecuzione, dalla cartella radice del progetto:
//   g++ -std=c++17 -DANT2_TEST_STANDALONE -I inet/src \
//       inet/src/inet/routing/ant2/test_controllo_hop.cc -o test_controllo_hop
//   ./test_controllo_hop
//
// Il corpo e' racchiuso in ANT2_TEST_STANDALONE perche' il makefile di INET
// compila tutti i .cc sotto src dentro libINET: senza questa protezione il
// main() di questo file finirebbe nella libreria e il collegamento fallirebbe.
#ifdef ANT2_TEST_STANDALONE

#include <cstdio>

#include "inet/routing/ant2/Ant2HopCheck.h"

using namespace ant2hop;

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

static void stampa(const std::vector<HopOutcome>& r)
{
    for (auto& o : r)
        std::printf("        %s  %s  %s\n", o.controllo.c_str(), esitoStr(o.esito), o.dettaglio.c_str());
}

static Esito esitoDi(const std::vector<HopOutcome>& r)
{
    return r.empty() ? Esito::NON_APPLICABILE : r[0].esito;
}

int main()
{
    HopCheckParams p;
    const bool DAL_CREATORE = true, INOLTRATO = false;

    std::printf("Regola 6: il numero di hop dichiarato\n\n");

    std::printf("== Controllo locale: chi trasmette contro chi ha creato ==\n");
    {
        HopObservedState st;
        auto r = checkHopLocale(st, 1, DAL_CREATORE, p); stampa(r);
        verifica(esitoDi(r) == Esito::SUPERATO, "ricevuto dal creatore e dichiarato 1 hop: SUPERATO");
    }
    {
        HopObservedState st;
        auto r = checkHopLocale(st, 3, DAL_CREATORE, p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO, "ricevuto dal creatore ma dichiara 3 hop: VIOLATO certo");
    }
    {
        HopObservedState st;
        auto r = checkHopLocale(st, 2, INOLTRATO, p); stampa(r);
        verifica(esitoDi(r) == Esito::SUPERATO, "inoltrato e dichiarato 2 hop: SUPERATO");
        auto r5 = checkHopLocale(st, 5, INOLTRATO, p);
        verifica(esitoDi(r5) == Esito::SUPERATO, "inoltrato e dichiarato 5 hop: SUPERATO");
    }
    {
        // E' l'attacco attackHopDistance: inoltra senza incrementare, cosi' i
        // nodi a valle lo credono adiacente e gli alzano il feromone.
        HopObservedState st;
        auto r = checkHopLocale(st, 1, INOLTRATO, p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO, "inoltra dichiarando 1 hop: VIOLATO certo");
        verifica(st.violati == 1, "la violazione e' contata");
    }
    {
        HopObservedState st;
        auto r = checkHopLocale(st, 0, INOLTRATO, p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO, "zero hop: VIOLATO, non e' un valore possibile");
        auto r2 = checkHopLocale(st, -1, DAL_CREATORE, p);
        verifica(esitoDi(r2) == Esito::VIOLATO, "hop negativi: VIOLATO");
    }
    {
        // Un nodo onesto, 200 messaggi misti, non deve produrre violazioni.
        HopObservedState st;
        for (int i = 0; i < 200; i++) {
            if (i % 3 == 0)
                checkHopLocale(st, 1, DAL_CREATORE, p);
            else
                checkHopLocale(st, 2 + (i % 4), INOLTRATO, p);
        }
        verifica(st.violati == 0 && st.superati == 200, "200 messaggi onesti: nessuna violazione");
    }

    std::printf("\n== Catena delle tracce: dove si rompe la numerazione ==\n");
    {
        std::vector<VoceCatena> c = { {1, 1}, {2, 2}, {3, 3}, {4, 4} };
        verifica(analizzaCatena(c).empty(), "catena corretta 1,2,3,4: nessuna coppia sospetta");
    }
    {
        // Il nodo 3 non incrementa: riceve con 3 ma la voce dice 2.
        std::vector<VoceCatena> c = { {1, 1}, {2, 2}, {3, 2}, {4, 4} };
        auto s = analizzaCatena(c);
        std::printf("        coppie sospette: %zu\n", s.size());
        verifica(s.size() == 1, "una sola rottura: una coppia sospetta");
        verifica(s[0].precedente == 2 && s[0].successivo == 3,
                 "la coppia accusata e' (2,3): da una catena sola non si sa quale dei due");
        verifica(s[0].atteso == 3 && s[0].trovato == 2, "atteso 3, trovato 2");
    }
    {
        // Mancato incremento che si propaga: tutte le voci a valle slittano.
        std::vector<VoceCatena> c = { {1, 1}, {2, 2}, {3, 2}, {4, 3}, {5, 4} };
        auto s = analizzaCatena(c);
        verifica(s.size() == 3, "lo slittamento rende sospette tutte le coppie a valle");
    }
    {
        std::vector<VoceCatena> c = { {1, 1} };
        verifica(analizzaCatena(c).empty(), "catena di un solo nodo: niente da confrontare");
    }

    std::printf("\n== Attribuzione: il colpevole e le sue vittime ==\n");
    {
        // Lo scenario misurato in simulazione: l'attaccante compare come
        // PRECEDENTE in 18 coppie, con due successori diversi.
        HopObservedState colpevole;
        colpevole.catene = 31;
        for (int i = 0; i < 10; i++) annotaCoppiaSospetta(colpevole, Ruolo::PRECEDENTE, "adh[14]");
        for (int i = 0; i < 8; i++)  annotaCoppiaSospetta(colpevole, Ruolo::PRECEDENTE, "adh[11]");
        auto r = verdettoCatena(colpevole, p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO, "precedente in 18 coppie con 2 vicini diversi: VIOLATO");
        verifica(colpevole.violati == 1, "la violazione e' contata");
    }
    {
        // La vittima: compare come SUCCESSIVA, sempre accanto allo stesso nodo.
        // Con il solo rapporto fra coppie e catene verrebbe accusata anche lei,
        // perche' 10 su 19 e' piu' della meta': e' il falso positivo misurato.
        HopObservedState vittima;
        vittima.catene = 19;
        for (int i = 0; i < 10; i++) annotaCoppiaSospetta(vittima, Ruolo::SUCCESSIVO, "adh[7]");
        auto r = verdettoCatena(vittima, p); stampa(r);
        verifica(esitoDi(r) == Esito::DUBBIO, "sempre dietro lo stesso vicino: DUBBIO, non si accusa");
        verifica(vittima.violati == 0, "la vittima non viene accusata");
    }
    {
        // Chi mente sulla propria voce sbaglia dietro a predecessori diversi.
        HopObservedState bugiardo;
        bugiardo.catene = 20;
        for (int i = 0; i < 6; i++) annotaCoppiaSospetta(bugiardo, Ruolo::SUCCESSIVO, "adh[1]");
        for (int i = 0; i < 6; i++) annotaCoppiaSospetta(bugiardo, Ruolo::SUCCESSIVO, "adh[2]");
        auto r = verdettoCatena(bugiardo, p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO, "successivo dietro 2 vicini diversi: VIOLATO");
    }
    {
        // Poche coppie: anche con vicini diversi non basta.
        HopObservedState poche;
        poche.catene = 4;
        annotaCoppiaSospetta(poche, Ruolo::PRECEDENTE, "adh[1]");
        annotaCoppiaSospetta(poche, Ruolo::PRECEDENTE, "adh[2]");
        auto r = verdettoCatena(poche, p);
        verifica(esitoDi(r) == Esito::DUBBIO, "2 coppie sole: sotto il minimo di campione, DUBBIO");
    }
    {
        HopObservedState pulito;
        pulito.catene = 30;
        verifica(verdettoCatena(pulito, p).empty(), "nessuna coppia sospetta: nessun esito");
    }
    {
        // Il verdetto non si ripete.
        HopObservedState st;
        st.catene = 20;
        for (int i = 0; i < 10; i++) annotaCoppiaSospetta(st, Ruolo::PRECEDENTE, "adh[1]");
        for (int i = 0; i < 8; i++)  annotaCoppiaSospetta(st, Ruolo::PRECEDENTE, "adh[2]");
        verdettoCatena(st, p);
        auto r = verdettoCatena(st, p);
        verifica(r.empty() && st.violati == 1, "verdetto emesso una volta sola");
    }

    std::printf("\n%d test eseguiti, %d falliti\n", eseguiti, falliti);
    return falliti == 0 ? 0 : 1;
}

#endif // ANT2_TEST_STANDALONE
