//
// test_controllo_disponibilita.cc
//
// Test automatici della regola 3 della metrica di trust (controllo sulla
// disponibilita' dichiarata nei BANT). Verificano la logica pura di
// Ant2AvailabilityCheck.h, senza OMNeT++ e senza INET.
//
// Compilazione ed esecuzione, dalla cartella radice del progetto:
//   g++ -std=c++17 -DANT2_TEST_STANDALONE -I inet/src \
//       inet/src/inet/routing/ant2/test_controllo_disponibilita.cc -o test_controllo_disponibilita
//   ./test_controllo_disponibilita
//
// Il corpo e' racchiuso in ANT2_TEST_STANDALONE perche' il makefile di INET
// compila tutti i .cc sotto src dentro libINET: senza questa protezione il main()
// di questo file finirebbe nella libreria e il collegamento fallirebbe.
#ifdef ANT2_TEST_STANDALONE

#include <cstdio>

#include "inet/routing/ant2/Ant2AvailabilityCheck.h"

using namespace ant2availability;

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

static void stampa(const std::vector<AvailabilityOutcome>& r)
{
    for (auto& o : r)
        std::printf("        %s  %s  %s\n", o.controllo.c_str(), esitoStr(o.esito), o.dettaglio.c_str());
}

static Esito esitoDi(const std::vector<AvailabilityOutcome>& r)
{
    return r.empty() ? Esito::NON_APPLICABILE : r[0].esito;
}

static bool vuoto(const std::vector<AvailabilityOutcome>& r) { return r.empty(); }

static AvailabilitySample S(double t, bool disponibile)
{
    AvailabilitySample s;
    s.t = t; s.disponibile = disponibile;
    return s;
}

int main()
{
    std::printf("== Drone onesto disponibile ==\n");
    {
        AvailabilityObservedState st;
        auto r = checkAvailability(st, S(5.0, true)); stampa(r);
        verifica(vuoto(r), "prima dichiarazione: presa per riferimento, nessun esito");
        verifica(st.atteso == Stato::DISPONIBILE, "lo stato atteso diventa disponibile");

        r = checkAvailability(st, S(8.0, true)); stampa(r);
        verifica(esitoDi(r) == Esito::SUPERATO, "seconda dichiarazione coerente: SUPERATO");

        // Ogni dichiarazione coerente conta come controllo superato: lo stato
        // atteso e' un riferimento esterno al drone, che non si sposta quando
        // mente, quindi chi mente non puo' superarlo e l'esito non e' gratuito.
        int superati = 0, sospetti = 0;
        double t = 8.0;
        for (int i = 0; i < 20; i++) {
            t += 2.5;
            for (auto& e : checkAvailability(st, S(t, true))) {
                if (e.esito == Esito::SUPERATO) superati++;
                else if (e.esito == Esito::VIOLATO || e.esito == Esito::DUBBIO) sospetti++;
            }
        }
        std::printf("        superati %d, sospetti %d in altre 20 dichiarazioni uguali\n", superati, sospetti);
        verifica(superati == 20 && sospetti == 0,
                 "dichiarazioni ripetute coerenti: un controllo superato ciascuna, nessun sospetto");
    }

    std::printf("\n== Drone reclutato: dopo lo spostamento deve dichiararsi non disponibile ==\n");
    {
        AvailabilityObservedState st;
        checkAvailability(st, S(5.0, true));
        checkAvailability(st, S(8.0, true));
        // La regola 2 conferma lo spostamento di reclutamento al timbro 12 s.
        aggiornaStato(st, Mossa::RECLUTAMENTO, 12.0);
        verifica(st.atteso == Stato::IMPEGNATO, "lo spostamento confermato rende il drone impegnato");

        auto r = checkAvailability(st, S(12.0, false)); stampa(r);
        verifica(esitoDi(r) == Esito::SUPERATO, "si dichiara non disponibile dopo lo spostamento: SUPERATO");

        r = checkAvailability(st, S(15.0, true)); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO,
                 "torna a dichiararsi disponibile senza congedo: VIOLATO");
    }
    {
        // L'attaccante si dichiara sempre disponibile. Fino allo spostamento non
        // si puo' dire niente, dopo ogni dichiarazione e' una violazione.
        AvailabilityObservedState st;
        checkAvailability(st, S(5.0, true));
        auto r = checkAvailability(st, S(8.0, true));
        verifica(esitoDi(r) == Esito::SUPERATO, "prima del reclutamento dichiararsi disponibile e' lecito");

        aggiornaStato(st, Mossa::RECLUTAMENTO, 12.0);
        int violazioni = 0;
        double t = 11.0;
        for (int i = 0; i < 10; i++) {
            t += 2.5;
            for (auto& o : checkAvailability(st, S(t, true)))
                if (o.esito == Esito::VIOLATO)
                    violazioni++;
        }
        std::printf("        violazioni su 10 dichiarazioni dopo lo spostamento: %d\n", violazioni);
        verifica(violazioni == 10,
                 "ogni dichiarazione falsa dopo lo spostamento e' una violazione (ognuna lo fa partecipare a un reclutamento)");
    }

    std::printf("\n== Ricarica: andata, permanenza e ritorno ==\n");
    {
        AvailabilityObservedState st;
        checkAvailability(st, S(5.0, true));
        checkAvailability(st, S(8.0, true));

        aggiornaStato(st, Mossa::ANDATA_STAZIONE, 20.0);
        verifica(st.atteso == Stato::IN_RICARICA, "l'arrivo alla stazione confermato mette il drone in ricarica");
        auto r = checkAvailability(st, S(20.0, false)); stampa(r);
        verifica(esitoDi(r) == Esito::SUPERATO, "alla stazione si dichiara non disponibile: SUPERATO");

        r = checkAvailability(st, S(23.0, true)); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO, "si dichiara disponibile mentre e' alla stazione: VIOLATO");

        // Ritorno dalla stazione: il codice ripristina il valore di prima, che
        // per questo drone era vero.
        aggiornaStato(st, Mossa::RITORNO_STAZIONE, 60.0);
        verifica(st.atteso == Stato::DISPONIBILE, "dopo il ritorno dalla stazione torna disponibile");
        r = checkAvailability(st, S(60.0, true)); stampa(r);
        verifica(esitoDi(r) == Esito::SUPERATO, "dopo il ritorno si dichiara disponibile: SUPERATO");
    }
    {
        // Un drone reclutato che poi va a ricaricarsi NON deve tornare
        // disponibile al ritorno: il codice ripristina preChargeAccept, che era
        // falso.
        AvailabilityObservedState st;
        checkAvailability(st, S(5.0, true));
        aggiornaStato(st, Mossa::RECLUTAMENTO, 12.0);
        checkAvailability(st, S(12.0, false));
        aggiornaStato(st, Mossa::ANDATA_STAZIONE, 40.0);
        aggiornaStato(st, Mossa::RITORNO_STAZIONE, 80.0);
        verifica(st.atteso == Stato::IMPEGNATO,
                 "reclutato prima della ricarica: al ritorno resta impegnato, come preChargeAccept");
        auto r = checkAvailability(st, S(80.0, true)); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO,
                 "si dichiara disponibile al ritorno dalla ricarica pur essendo impegnato: VIOLATO");
    }

    std::printf("\n== Nessun falso positivo quando chi controlla si perde un REQ ==\n");
    {
        // Il drone viene reclutato, ma chi controlla non ha ricevuto il REQ e
        // non ha osservato lo spostamento (per esempio perche' non ha ricevuto
        // i BANT nell'intervallo giusto). Il drone dichiara non disponibile: non
        // deve essere punito.
        AvailabilityObservedState st;
        checkAvailability(st, S(5.0, true));
        checkAvailability(st, S(8.0, true));
        auto r = checkAvailability(st, S(14.0, false)); stampa(r);
        verifica(esitoDi(r) == Esito::NON_APPLICABILE,
                 "si dichiara non disponibile senza spostamento osservato: NON_APPLICABILE, non violazione");
        verifica(st.atteso == Stato::NON_DISPONIBILE,
                 "chi controlla si adegua: da ora lo considera non disponibile, con il motivo non osservato");

        // Se poi torna a dichiararsi disponibile, la contraddizione e' sua.
        r = checkAvailability(st, S(17.0, true)); stampa(r);
        verifica(esitoDi(r) == Esito::DUBBIO,
                 "dopo essersi dichiarato non disponibile torna disponibile: DUBBIO, non violazione certa, perche' potrebbe essersi ricaricato senza farsi vedere");
    }
    {
        // Un drone del cluster 1, che nel file di configurazione non e'
        // reclutabile, dichiara sempre non disponibile: nessun esito negativo.
        AvailabilityObservedState st;
        int negativi = 0;
        double t = 0;
        for (int i = 0; i < 25; i++) {
            t += 2.4;
            for (auto& o : checkAvailability(st, S(t, false)))
                if (o.esito == Esito::VIOLATO)
                    negativi++;
        }
        verifica(negativi == 0,
                 "drone mai reclutabile che dichiara sempre non disponibile: nessuna violazione");
        verifica(st.atteso == Stato::NON_DISPONIBILE,
                 "la prima dichiarazione falsa diventa il riferimento, senza conoscere la configurazione");
    }

    std::printf("\n== Certo o dubbio, a seconda di come e' stato stabilito lo stato ==\n");
    {
        // Stato stabilito da uno spostamento verificato: la contraddizione e' certa.
        AvailabilityObservedState a;
        checkAvailability(a, S(5.0, true));
        aggiornaStato(a, Mossa::RECLUTAMENTO, 12.0);
        verifica(a.statoVerificato, "lo spostamento verificato marca lo stato come certo");
        auto r = checkAvailability(a, S(15.0, true));
        verifica(esitoDi(r) == Esito::VIOLATO, "stato verificato e dichiarazione contraria: VIOLATO");

        // Stato dedotto da una dichiarazione del drone: la contraddizione e'
        // dubbia, perche' il drone potrebbe essersi ricaricato di nascosto e il
        // codice al ritorno dalla stazione ripristina la disponibilita'.
        AvailabilityObservedState b;
        checkAvailability(b, S(5.0, false));
        verifica(!b.statoVerificato, "uno stato dedotto da una dichiarazione non e' certo");
        r = checkAvailability(b, S(8.0, true));
        verifica(esitoDi(r) == Esito::DUBBIO, "stato dedotto e dichiarazione contraria: DUBBIO");
    }

    std::printf("\n== Misure ripetute e in disordine ==\n");
    {
        AvailabilityObservedState st;
        checkAvailability(st, S(5.0, true));
        checkAvailability(st, S(8.0, true));
        auto r = checkAvailability(st, S(8.0, true));
        verifica(vuoto(r), "stesso timbro con lo stesso valore: nessun esito");

        r = checkAvailability(st, S(6.0, false));
        verifica(vuoto(r), "timbro piu' vecchio dell'ultimo: nessun esito");
        verifica(st.atteso == Stato::DISPONIBILE,
                 "una dichiarazione in disordine non cambia lo stato atteso");

        r = checkAvailability(st, S(-1.0, true));
        verifica(vuoto(r), "misura mai eseguita (timbro negativo): nessun esito");
    }
    {
        // Lo stesso timbro con un valore diverso non deve essere contato due
        // volte, ma se il valore e' falso quando lo stato atteso dice impegnato
        // la violazione non si ripete sullo stesso timbro.
        AvailabilityObservedState st;
        checkAvailability(st, S(5.0, true));
        aggiornaStato(st, Mossa::RECLUTAMENTO, 10.0);
        auto r1 = checkAvailability(st, S(10.0, true));
        auto r2 = checkAvailability(st, S(10.0, true));
        verifica(esitoDi(r1) == Esito::VIOLATO && vuoto(r2),
                 "la violazione sullo stesso timbro viene contata una volta sola");
    }

    std::printf("\n%d test eseguiti, %d falliti\n", eseguiti, falliti);
    return falliti == 0 ? 0 : 1;
}

#endif // ANT2_TEST_STANDALONE
