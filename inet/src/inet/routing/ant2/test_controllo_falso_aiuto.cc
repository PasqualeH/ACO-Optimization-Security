//
// test_controllo_falso_aiuto.cc
//
// Test automatici della regola 4 della metrica di trust (controllo sul falso
// aiuto). Verificano la logica pura di Ant2HelpCheck.h, senza OMNeT++ e senza
// INET.
//
// Compilazione ed esecuzione, dalla cartella radice del progetto:
//   g++ -std=c++17 -DANT2_TEST_STANDALONE -I inet/src \
//       inet/src/inet/routing/ant2/test_controllo_falso_aiuto.cc -o test_controllo_falso_aiuto
//   ./test_controllo_falso_aiuto
//
// Il corpo e' racchiuso in ANT2_TEST_STANDALONE perche' il makefile di INET
// compila tutti i .cc sotto src dentro libINET: senza questa protezione il main()
// di questo file finirebbe nella libreria e il collegamento fallirebbe.
#ifdef ANT2_TEST_STANDALONE

#include <cstdio>

#include "inet/routing/ant2/Ant2HelpCheck.h"

using namespace ant2help;

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

static void stampa(const std::vector<HelpOutcome>& r)
{
    for (auto& o : r)
        std::printf("        %s  %s  %s\n", o.controllo.c_str(), esitoStr(o.esito), o.dettaglio.c_str());
}

static Esito esitoDi(const std::vector<HelpOutcome>& r)
{
    return r.empty() ? Esito::NON_APPLICABILE : r[0].esito;
}

static bool vuoto(const std::vector<HelpOutcome>& r) { return r.empty(); }

int main()
{
    HelpCheckParams p;              // D = 3 s, ritardo mossa 1 s
    const uint32_t VINCITORE = 7;
    const uint32_t RICHIEDENTE = 2;
    const uint32_t ALTRO = 4;

    std::printf("Parametri: D = %.0f s, ritardo dello spostamento = %.0f s\n", p.maxNetworkDelay, p.recruitMoveDelay);
    std::printf("REQ ricevuto a 17.000 s -> istante limite 21.000 s\n\n");

    std::printf("== L'istante limite ==\n");
    {
        auto a = nuovaAttesa(VINCITORE, RICHIEDENTE, 17.0, 1, true, p);
        verifica(std::abs(a.istanteLimite - 21.0) < 1e-9,
                 "istante limite = t_R + D + ritardo dello spostamento = 21,000 s");

        std::vector<Pending> attese{a};
        Contesto c;
        c.disponibileDichiarata = true;
        auto r = checkHelp(attese, VINCITORE, 19.0, c, p);
        verifica(vuoto(r), "BANT con timbro 19 s, prima del limite: nessun esito, si continua ad aspettare");
        verifica(!attese[0].risolto, "la verifica resta aperta");

        r = checkHelp(attese, VINCITORE, 21.5, c, p);
        verifica(!vuoto(r), "BANT con timbro 21,5 s, oltre il limite: il controllo viene eseguito");
        verifica(attese[0].risolto, "la verifica viene chiusa");

        r = checkHelp(attese, VINCITORE, 24.0, c, p);
        verifica(vuoto(r), "un secondo BANT non riapre la verifica gia' chiusa");
    }

    std::printf("\n== Il drone si sposta e presta aiuto ==\n");
    {
        std::vector<Pending> attese{nuovaAttesa(VINCITORE, RICHIEDENTE, 17.0, 1, true, p)};
        // La regola 2 conferma lo spostamento verso chi ha chiesto aiuto.
        segnalaSpostamento(attese, VINCITORE, RICHIEDENTE, true, false);
        Contesto c;
        c.disponibileDichiarata = false;   // reclutato, quindi non piu' disponibile
        auto r = checkHelp(attese, VINCITORE, 21.5, c, p); stampa(r);
        verifica(esitoDi(r) == Esito::SUPERATO, "spostamento confermato dalla regola 2: SUPERATO");
    }
    {
        // Lo spostamento confermato verso un ALTRO richiedente non chiude questa
        // verifica come superata.
        std::vector<Pending> attese{nuovaAttesa(VINCITORE, RICHIEDENTE, 17.0, 1, true, p)};
        segnalaSpostamento(attese, VINCITORE, ALTRO, true, false);
        Contesto c;
        c.disponibileDichiarata = false;
        auto r = checkHelp(attese, VINCITORE, 21.5, c, p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO,
                 "spostamento verso un altro richiedente: non vale come aiuto a questo");
    }

    std::printf("\n== Falso aiuto: accetta e non si sposta ==\n");
    {
        std::vector<Pending> attese{nuovaAttesa(VINCITORE, RICHIEDENTE, 17.0, 1, true, p)};
        Contesto c;
        c.disponibileDichiarata = false;   // si comporta come se avesse accettato
        auto r = checkHelp(attese, VINCITORE, 21.5, c, p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO,
                 "si dichiara non disponibile ma non si e' spostato: VIOLATO certo");
    }
    {
        // Essere reclutato DOPO non giustifica il non avere aiutato prima.
        std::vector<Pending> attese{nuovaAttesa(VINCITORE, RICHIEDENTE, 17.0, 1, true, p),
                                    nuovaAttesa(VINCITORE, ALTRO, 30.0, 2, true, p)};
        Contesto c;
        c.disponibileDichiarata = false;
        auto r = checkHelp(attese, VINCITORE, 21.5, c, p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO,
                 "un reclutamento successivo non giustifica il non avere aiutato prima: VIOLATO");
    }

    std::printf("\n== Reclutamento precedente in corso (il caso di adh[11]) ==\n");
    {
        // Caso visto nella simulazione TestFalsoAiutoOnesto: adh[11] accetta la
        // richiesta di adh[4] a 27,938 s, si sposta a 28,938 s, e a 28,993 s
        // RIFIUTA la richiesta di adh[8] perche' non e' piu' disponibile,
        // limitandosi a inoltrarla. Chi controlla apre una verifica anche per il
        // REQ rifiutato, e non deve contarla come violazione.
        //
        // Lo stato atteso della regola 3 non basta a riconoscerlo: diventa
        // "impegnato" solo quando la regola 2 conferma lo spostamento, cioe' al
        // timbro 29,295 s, dopo l'arrivo del secondo REQ. La prova sta nel
        // registro, dove il reclutamento precedente c'e' gia'.
        std::vector<Pending> attese{nuovaAttesa(VINCITORE, ALTRO, 27.917, 1, true, p),
                                    nuovaAttesa(VINCITORE, 8, 28.993, 2, true, p)};
        segnalaSpostamento(attese, VINCITORE, ALTRO, true, false);
        Contesto c;
        c.disponibileDichiarata = false;   // reclutato dal primo, quindi non disponibile
        auto r = checkHelp(attese, VINCITORE, 35.066, c, p); stampa(r);
        bool superato = false, nonApplicabile = false;
        for (auto& o : r) {
            if (o.esito == Esito::SUPERATO) superato = true;
            if (o.esito == Esito::NON_APPLICABILE) nonApplicabile = true;
        }
        verifica(r.size() == 2, "lo stesso BANT chiude entrambe le verifiche scadute");
        verifica(superato, "il primo reclutamento, onorato, risulta SUPERATO");
        verifica(nonApplicabile, "il secondo, rifiutato perche' gia' impegnato, risulta NON_APPLICABILE");
        bool violato = false;
        for (auto& o : r)
            if (o.esito == Esito::VIOLATO)
                violato = true;
        verifica(!violato, "nessuna violazione su un drone onesto reclutato due volte");
    }
    {
        // Il reclutamento precedente scusa solo quello successivo, non il
        // contrario: se il drone non ha onorato il primo, il primo e' violato.
        std::vector<Pending> attese{nuovaAttesa(VINCITORE, ALTRO, 27.917, 1, true, p),
                                    nuovaAttesa(VINCITORE, 8, 28.993, 2, true, p)};
        Contesto c;
        c.disponibileDichiarata = false;
        auto r = checkHelp(attese, VINCITORE, 35.066, c, p); stampa(r);
        int violati = 0;
        for (auto& o : r)
            if (o.esito == Esito::VIOLATO)
                violati++;
        verifica(violati == 1, "il primo reclutamento non onorato resta VIOLATO, il secondo e' scusato");
    }

    std::printf("\n== Richiesta ignorata, o mai ricevuta ==\n");
    {
        std::vector<Pending> attese{nuovaAttesa(VINCITORE, RICHIEDENTE, 17.0, 1, true, p)};
        Contesto c;
        c.disponibileDichiarata = true;    // continua a dichiararsi disponibile
        auto r = checkHelp(attese, VINCITORE, 21.5, c, p); stampa(r);
        verifica(esitoDi(r) == Esito::DUBBIO,
                 "non si e' spostato e si dichiara ancora disponibile: DUBBIO, non violazione certa");
    }

    std::printf("\n== I casi in cui il controllo non si applica ==\n");
    {
        // Non era disponibile nell'istante del REQ: un drone onesto ignora.
        std::vector<Pending> attese{nuovaAttesa(VINCITORE, RICHIEDENTE, 17.0, 1, false, p)};
        Contesto c;
        c.disponibileDichiarata = false;
        auto r = checkHelp(attese, VINCITORE, 21.5, c, p); stampa(r);
        verifica(esitoDi(r) == Esito::NON_APPLICABILE,
                 "non era disponibile quando e' stato scelto: NON_APPLICABILE, la colpa non e' sua");
    }
    {
        // E' andato a ricaricarsi: moveUav() in quel caso non sposta.
        std::vector<Pending> attese{nuovaAttesa(VINCITORE, RICHIEDENTE, 17.0, 1, true, p)};
        Contesto c;
        c.allaStazione = true;
        c.disponibileDichiarata = false;
        auto r = checkHelp(attese, VINCITORE, 21.5, c, p); stampa(r);
        verifica(esitoDi(r) == Esito::NON_APPLICABILE,
                 "risulta alla stazione di ricarica: NON_APPLICABILE, lo spostamento e' annullato dal codice");
    }
    {
        // La regola 2 ha gia' segnalato il suo spostamento: non si punisce due volte.
        std::vector<Pending> attese{nuovaAttesa(VINCITORE, RICHIEDENTE, 17.0, 1, true, p)};
        segnalaSpostamento(attese, VINCITORE, RICHIEDENTE, false, true);
        Contesto c;
        c.disponibileDichiarata = false;
        auto r = checkHelp(attese, VINCITORE, 21.5, c, p); stampa(r);
        verifica(esitoDi(r) == Esito::NON_APPLICABILE,
                 "spostamento gia' segnalato dalla regola 2: NON_APPLICABILE");
    }

    std::printf("\n== Verifiche abbandonate ==\n");
    {
        std::vector<Pending> attese{nuovaAttesa(VINCITORE, RICHIEDENTE, 17.0, 1, true, p)};
        int abbandonate = ripulisciAttese(attese, 50.0, p);
        verifica(abbandonate == 0 && attese.size() == 1,
                 "entro l'attesa massima la verifica resta aperta");

        abbandonate = ripulisciAttese(attese, 100.0, p);
        verifica(abbandonate == 1 && attese.empty(),
                 "oltre l'attesa massima senza nessun BANT utile la verifica viene abbandonata e contata");

        std::vector<Pending> attese2{nuovaAttesa(VINCITORE, RICHIEDENTE, 17.0, 1, true, p)};
        Contesto c;
        checkHelp(attese2, VINCITORE, 21.5, c, p);
        abbandonate = ripulisciAttese(attese2, 30.0, p);
        verifica(abbandonate == 0 && attese2.size() == 1,
                 "una verifica chiusa resta nell'elenco: serve da storia per i reclutamenti successivi");
        abbandonate = ripulisciAttese(attese2, 100.0, p);
        verifica(abbandonate == 0 && attese2.empty(),
                 "quando e' abbastanza vecchia viene scartata, senza essere contata fra le abbandonate");
    }

    std::printf("\n== Piu' droni osservati insieme ==\n");
    {
        std::vector<Pending> attese{nuovaAttesa(VINCITORE, RICHIEDENTE, 17.0, 1, true, p),
                                    nuovaAttesa(9, RICHIEDENTE, 17.0, 2, true, p)};
        segnalaSpostamento(attese, 9, RICHIEDENTE, true, false);
        Contesto c;
        c.disponibileDichiarata = false;
        auto r = checkHelp(attese, 9, 21.5, c, p);
        verifica(esitoDi(r) == Esito::SUPERATO, "il BANT di un drone chiude solo le verifiche che lo riguardano");
        verifica(!attese[0].risolto, "la verifica dell'altro drone resta aperta");

        r = checkHelp(attese, VINCITORE, 21.5, c, p);
        verifica(esitoDi(r) == Esito::VIOLATO, "il secondo drone viene verificato quando arriva il suo BANT");
    }

    std::printf("\n== Prova riferita dalla GCS: puo' scagionare, non accusare ==\n");
    {
        // Lo stesso scenario che di persona produce una violazione certa.
        std::vector<Pending> attese;
        attese.push_back(nuovaAttesa(7, 1, 10.0, 5, true, p));
        Contesto c; c.allaStazione = false; c.disponibileDichiarata = false;
        auto r = checkHelp(attese, 7, 20.0, c, p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO, "REQ osservato di persona: VIOLATO certo");
    }
    {
        // Identico, ma il REQ e' stato riferito dalla GCS nel bollettino: chi
        // controlla non ha assistito all'episodio, quindi non puo' escludere che
        // lo spostamento sia avvenuto senza che lui lo vedesse.
        std::vector<Pending> attese;
        attese.push_back(nuovaAttesa(7, 1, 10.0, 5, true, p, true));
        Contesto c; c.allaStazione = false; c.disponibileDichiarata = false;
        auto r = checkHelp(attese, 7, 20.0, c, p); stampa(r);
        verifica(esitoDi(r) == Esito::DUBBIO, "REQ riferito dalla GCS: DUBBIO, non accusa");
    }
    {
        // Una prova di seconda mano continua a SCAGIONARE: se il drone non era
        // disponibile all'istante del REQ, l'esito resta non applicabile.
        std::vector<Pending> attese;
        attese.push_back(nuovaAttesa(7, 1, 10.0, 5, false, p, true));
        Contesto c; c.allaStazione = false; c.disponibileDichiarata = false;
        auto r = checkHelp(attese, 7, 20.0, c, p);
        verifica(esitoDi(r) == Esito::NON_APPLICABILE,
                 "prova di seconda mano: scagiona ancora, non applicabile");
    }
    {
        // E se lo spostamento viene confermato, il seconda mano non impedisce
        // l'esito positivo.
        std::vector<Pending> attese;
        attese.push_back(nuovaAttesa(7, 1, 10.0, 5, true, p, true));
        attese[0].spostamentoConfermato = true;
        Contesto c; c.allaStazione = false; c.disponibileDichiarata = false;
        auto r = checkHelp(attese, 7, 20.0, c, p);
        verifica(esitoDi(r) == Esito::SUPERATO, "spostamento confermato: SUPERATO anche se riferito");
    }

    std::printf("\n%d test eseguiti, %d falliti\n", eseguiti, falliti);
    return falliti == 0 ? 0 : 1;
}

#endif // ANT2_TEST_STANDALONE
