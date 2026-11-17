//
// test_controllo_energia.cc - test automatici della regola 1 (controllo
// sull'energia), sulla stessa funzione checkEnergy() di Ant2EnergyCheck.h
// usata dal protocollo.
//
// Come microbench.cc e test_energia.cc, tutto il file e' racchiuso in una
// #ifdef, cosi' la build di INET lo compila come file vuoto. Per eseguirlo:
//
//   g++ -std=c++17 -DANT2_TEST_STANDALONE -I<cartella src di INET>
//       test_controllo_energia.cc -o test_controllo_energia  (poi ./test_controllo_energia)
//

#ifdef ANT2_TEST_STANDALONE

#include <cstdio>
#include <cmath>
#include "inet/routing/ant2/Ant2EnergyCheck.h"

using namespace inet::ant2energy;

static int falliti = 0, eseguiti = 0;

static void verifica(bool c, const char *d)
{
    eseguiti++;
    if (!c)
        falliti++;
    std::printf("[%s] %s\n", c ? " OK " : "FAIL", d);
}

// Esito del controllo con quel nome nell'elenco (NON_APPLICABILE se assente).
static Esito esitoDi(const std::vector<EnergyOutcome>& v, const char *nome)
{
    for (auto& o : v)
        if (o.controllo == nome)
            return o.esito;
    return Esito::NON_APPLICABILE;
}

static bool nessunaViolazione(const std::vector<EnergyOutcome>& v)
{
    for (auto& o : v)
        if (o.esito == Esito::VIOLATO)
            return false;
    return true;
}

static void stampa(const std::vector<EnergyOutcome>& v)
{
    for (auto& o : v)
        std::printf("        %-20s %-16s %s\n", o.controllo.c_str(), esitoStr(o.esito), o.dettaglio.c_str());
}

// diretto vale true per difetto: nei casi di prova il messaggio arriva dal nodo
// che lo ha firmato, che e' la situazione normale. Il caso del messaggio
// inoltrato da un terzo ha una prova sua.
static EnergySample S(double t, double arrival, double pct, bool stazione = false,
                      const char *fonte = "BANT", bool diretto = true)
{
    EnergySample s;
    s.t = t; s.arrival = arrival; s.pct = pct; s.atStation = stazione; s.fonte = fonte;
    s.diretto = diretto;
    return s;
}

static bool vicino(double a, double b, double tol = 1e-4)
{
    return std::fabs(a - b) <= tol;
}

int main()
{
    // Parametri del progetto: batteria 3 J, radio 2-100 mW, caricatore 100 mW,
    // W = 30 s, eta' massima del timbro 3 s + D (D = 1 s).
    EnergyCheckParams p;
    p.capacityJ = 3.0; p.pMinW = 0.002; p.pMaxW = 0.100; p.chargeW = 0.100;
    p.tolPct = 0.01; p.windowS = 30; p.maxAgeS = 4.0; p.chargeThresholdPct = 15;
    std::printf("Calo minimo %.4f %%/s, calo massimo %.4f %%/s, ricarica %.4f %%/s\n\n",
                p.minRate(), p.maxRate(), p.chargeRate());

    std::printf("== Drone onesto ==\n");
    {
        EnergyObservedState st;
        auto r = checkEnergy(st, S(10.0, 10.4, 80.00), p);
        verifica(nessunaViolazione(r) && st.has, "prima misura (80,00% a 10,0 s): solo memorizzata");
        r = checkEnergy(st, S(11.8, 12.9, 79.85), p); stampa(r);
        verifica(esitoDi(r, "andamento") == Esito::SUPERATO, "79,85% a 11,8 s: calo 0,15% in 1,8 s, dentro [0,12% ; 6%]");
        r = checkEnergy(st, S(11.8, 13.5, 79.85), p);
        verifica(esitoDi(r, "misura") == Esito::NON_APPLICABILE && nessunaViolazione(r), "stesso timbro 11,8 s: misura ripetuta, non applicabile");
        r = checkEnergy(st, S(11.0, 13.6, 79.90), p);
        verifica(nessunaViolazione(r) && st.last.t == 11.8, "timbro 11,0 s dopo 11,8 s: in disordine, ignorata");
        r = checkEnergy(st, S(40.0, 40.3, 77.10), p); stampa(r);
        verifica(esitoDi(r, "calo minimo") == Esito::SUPERATO, "77,10% a 40,0 s: calo 2,9% in 30 s, almeno 2% richiesto");
    }

    std::printf("\n== Attaccante che gonfia l'energia (fase C) ==\n");
    {
        EnergyObservedState st;
        checkEnergy(st, S(10.0, 10.2, 80.00), p);
        auto r = checkEnergy(st, S(25.0, 25.2, 79.80), p);
        verifica(esitoDi(r, "andamento") == Esito::SUPERATO, "79,80% a 25 s: il calo e' piccolo ma l'andamento passo-passo e' ammesso");
        r = checkEnergy(st, S(40.0, 40.2, 79.50), p); stampa(r);
        verifica(esitoDi(r, "calo minimo") == Esito::VIOLATO, "79,50% a 40 s: calo 0,5% in 30 s contro un minimo di 2%: VIOLATO");
    }
    {
        EnergyObservedState st;
        int violazioni = 0;
        double primo = -1;
        for (double t = 2; t <= 120; t += 2) {
            auto r = checkEnergy(st, S(t, t + 0.3, 100.0), p);
            if (esitoDi(r, "calo minimo") == Esito::VIOLATO) {
                violazioni++;
                if (primo < 0) primo = t;
            }
        }
        std::printf("        energia sempre 100%%: %d violazioni del calo minimo, la prima a %.0f s\n", violazioni, primo);
        verifica(violazioni >= 3 && primo <= 34, "energia sempre al 100%: violazione a ogni finestra W, la prima entro ~32 s");
    }

    std::printf("\n== Attaccante che finge di essere scarico ==\n");
    {
        EnergyObservedState st;
        checkEnergy(st, S(11.8, 12.0, 79.85), p);
        auto r = checkEnergy(st, S(13.6, 13.9, 60.00), p); stampa(r);
        verifica(esitoDi(r, "andamento") == Esito::VIOLATO, "da 79,85% a 60% in 1,8 s: oltre il calo massimo di 6%: VIOLATO");
    }

    std::printf("\n== Energia che sale senza ricarica ==\n");
    {
        EnergyObservedState st;
        checkEnergy(st, S(40.0, 40.1, 77.10), p);
        auto r = checkEnergy(st, S(42.0, 42.1, 85.00), p); stampa(r);
        verifica(esitoDi(r, "andamento") == Esito::VIOLATO, "da 77,10% a 85% fuori dalla stazione: VIOLATO");
    }

    std::printf("\n== Ricarica alla stazione ==\n");
    {
        EnergyObservedState st;
        checkEnergy(st, S(48.0, 48.2, 15.10, false), p);
        checkEnergy(st, S(50.0, 50.2, 15.00, true), p);
        auto r = checkEnergy(st, S(80.0, 80.2, 35.00, true), p); stampa(r);
        verifica(esitoDi(r, "andamento") == Esito::SUPERATO, "alla stazione +20% in 30 s: dentro il massimo di ricarica");
        r = checkEnergy(st, S(85.0, 85.2, 70.00, true), p); stampa(r);
        verifica(esitoDi(r, "andamento") == Esito::VIOLATO, "alla stazione +35% in 5 s: oltre il massimo di ricarica (16,3%): VIOLATO");
        r = checkEnergy(st, S(90.0, 90.2, 99.0, false), p);
        verifica(esitoDi(r, "calo minimo") == Esito::NON_APPLICABILE, "uscita dalla stazione: nessun calo minimo, il riferimento riparte da qui");
        r = checkEnergy(st, S(121.0, 121.2, 96.5, false), p); stampa(r);
        verifica(esitoDi(r, "calo minimo") == Esito::SUPERATO, "31 s dopo il ritorno: calo minimo controllato di nuovo");
    }

    std::printf("\n== Ricarica avvenuta fuori dalla vista di chi controlla ==\n");
    {
        EnergyObservedState st;
        checkEnergy(st, S(10.0, 10.2, 20.00), p);
        auto r = checkEnergy(st, S(50.0, 50.2, 100.00), p); stampa(r);
        verifica(esitoDi(r, "andamento") == Esito::NON_APPLICABILE && nessunaViolazione(r),
                 "da 20% (10 s) a 100% (50 s): servono 1,5 + 26,0 s, ne sono passati 40: ricarica possibile, non applicabile");
        r = checkEnergy(st, S(81.0, 81.2, 97.50), p);
        verifica(esitoDi(r, "calo minimo") == Esito::SUPERATO, "97,50% a 81 s: il calo minimo riparte dalla misura dopo la ricarica (50 s), calo 2,5% contro 2,07%");
        EnergyObservedState st2;
        checkEnergy(st2, S(10.0, 10.2, 60.00), p);
        r = checkEnergy(st2, S(40.0, 40.2, 100.00), p); stampa(r);
        verifica(esitoDi(r, "andamento") == Esito::VIOLATO,
                 "da 60% a 100% in 30 s fuori dalla stazione: servono almeno 13,5 + 26,0 s, VIOLATO");
    }

    std::printf("\n== Coerenza del timbro ==\n");
    {
        EnergyObservedState st;
        auto r = checkEnergy(st, S(31.0, 30.0, 80.0), p); stampa(r);
        verifica(esitoDi(r, "coerenza del timbro") == Esito::VIOLATO, "timbro 31 s, arrivo 30 s: timbro nel futuro, VIOLATO");
        r = checkEnergy(st, S(35.0, 40.0, 80.0), p); stampa(r);
        verifica(esitoDi(r, "coerenza del timbro") == Esito::VIOLATO, "timbro 35 s, arrivo 40 s: piu' vecchio di 4 s, VIOLATO");

        // Messaggio INOLTRATO da un terzo: fra la lettura e l'arrivo c'e' il
        // tempo passato nelle code degli altri nodi, che non dipende da chi ha
        // scritto il dato. L'eta' del timbro non si controlla, altrimenti si
        // punisce la congestione del canale invece della malafede: e' il caso
        // che nello scenario finale aveva prodotto otto violazioni su un drone
        // onesto, il cui BANT era stato ritrasmesso sette secondi dopo.
        EnergyObservedState st2;
        r = checkEnergy(st2, S(26.0, 33.5, 80.0, false, "BANT", false), p); stampa(r);
        verifica(esitoDi(r, "coerenza del timbro") == Esito::NON_APPLICABILE,
                 "timbro vecchio di 7,5 s su un messaggio inoltrato: NON_APPLICABILE, non si punisce il ritardo della rete");

        // Il timbro nel futuro resta impossibile anche su un messaggio
        // inoltrato: nessun ritardo di rete puo' spiegarlo.
        EnergyObservedState st3;
        r = checkEnergy(st3, S(31.0, 30.0, 80.0, false, "BANT", false), p); stampa(r);
        verifica(esitoDi(r, "coerenza del timbro") == Esito::VIOLATO,
                 "timbro nel futuro su un messaggio inoltrato: VIOLATO comunque");
        r = checkEnergy(st, S(20.0, 22.9, 80.0), p);
        verifica(nessunaViolazione(r), "timbro 20 s, arrivo 22,9 s: dato vecchio ma onesto, coerente");
        r = checkEnergy(st, S(-1, 1.0, 50.0), p);
        verifica(esitoDi(r, "timbro") == Esito::NON_APPLICABILE, "timbro -1 (nessuna misura ancora fatta): non applicabile");
    }

    std::printf("\n== Valore ammesso ==\n");
    {
        EnergyObservedState st;
        auto r = checkEnergy(st, S(5.0, 5.1, 270.0), p);
        verifica(esitoDi(r, "valore ammesso") == Esito::VIOLATO, "270% (vecchia scala sbagliata): fuori da 0-100%, VIOLATO");
    }

    std::printf("\n== Controllo della GCS con l'energia iniziale ==\n");
    {
        EnergyCheckParams g = p;
        g.initialPct = 50.0;   // adh[7] parte dal 50%
        EnergyObservedState st;
        auto r = checkEnergy(st, S(5.0, 5.2, 100.0), g); stampa(r);
        verifica(esitoDi(r, "energia iniziale") == Esito::VIOLATO, "adh[7] dichiara 100% a 5 s partendo dal 50%: VIOLATO al primo BANT");
        EnergyObservedState st2;
        r = checkEnergy(st2, S(5.0, 5.2, 49.60), g); stampa(r);
        verifica(esitoDi(r, "energia iniziale") == Esito::SUPERATO, "drone onesto al 49,60% a 5 s (massimo 49,68%): SUPERATO");
        EnergyObservedState st3;
        r = checkEnergy(st3, S(15.0, 15.2, 49.50), g); stampa(r);
        verifica(esitoDi(r, "energia iniziale") == Esito::VIOLATO, "49,50% a 15 s: avrebbe dovuto perdere almeno l'1%, VIOLATO (bugia plausibile scoperta)");
        EnergyObservedState st4;
        r = checkEnergy(st4, S(60.0, 60.2, 95.00), g); stampa(r);
        verifica(esitoDi(r, "energia iniziale") == Esito::NON_APPLICABILE && nessunaViolazione(r),
                 "95% a 60 s come prima misura: una ricarica non vista era possibile (servono 35,0 s), non applicabile");
        r = checkEnergy(st4, S(62.0, 62.2, 100.00), g);
        verifica(esitoDi(r, "andamento") == Esito::VIOLATO, "subito dopo, +5% in 2 s fuori dalla stazione: VIOLATO");
    }

    std::printf("\n== Calo minimo ricavato dal traffico di protocollo ==\n");
    {
        // Scenario: 15 droni + 3 GCS = 18 nodi, un FANT ogni 5 s.
        EnergyCheckParams q = p;
        q.helloIntervalS = 5.0; q.networkNodes = 18; q.pRxW = 0.010;
        q.fantBytes = 80; q.bantBytes = 161;

        q.trafficMargin = 0.0;
        std::printf("        k = 0,0: calo minimo su 30 s = %.4f%% (solo ascolto)\n", q.minDrop(30));
        verifica(vicino(q.minDrop(30), p.minRate() * 30),
                 "con coefficiente 0 il calo minimo e' identico a quello precedente (2,000% in 30 s)");

        q.trafficMargin = 1.0;
        double tx = q.txTime(30), rx = q.rxTime(30);
        std::printf("        k = 1,0: trasmissione %.3f ms, ricezione %.3f ms, calo minimo %.4f%%\n",
                    tx * 1000, rx * 1000, q.minDrop(30));
        verifica(vicino(tx * 1000, 9.896, 0.01), "tempo in trasmissione su 30 s: 9,9 ms (216 messaggi)");
        verifica(vicino(rx * 1000, 4.095, 0.01), "tempo in ricezione su 30 s: 4,1 ms (102 generazioni altrui)");
        verifica(vicino(q.minDrop(30), 2.0334, 0.001), "calo minimo con traffico intero: 2,033% in 30 s");

        q.trafficMargin = 0.5;
        std::printf("        k = 0,5: calo minimo su 30 s = %.4f%%\n", q.minDrop(30));
        verifica(vicino(q.minDrop(30), 2.0167, 0.001), "calo minimo con coefficiente di prudenza 0,5: 2,017% in 30 s");

        // Un drone onesto che consuma 2,12% in 30 s passa comunque.
        {
            EnergyObservedState st;
            checkEnergy(st, S(10.0, 10.2, 80.00), q);
            auto r = checkEnergy(st, S(40.0, 40.2, 77.88), q); stampa(r);
            verifica(esitoDi(r, "calo minimo") == Esito::SUPERATO,
                     "drone onesto che consuma 2,12% in 30 s: SUPERATO (consumo misurato dei droni onesti)");
        }
        // Un attaccante che dichiara esattamente il vecchio minimo ora viene preso.
        {
            EnergyObservedState st;
            checkEnergy(st, S(10.0, 10.2, 80.00), q);
            auto r = checkEnergy(st, S(40.0, 40.2, 78.00), q); stampa(r);
            verifica(esitoDi(r, "calo minimo") == Esito::VIOLATO,
                     "chi dichiara un calo di 2,00% in 30 s: VIOLATO con il traffico, era SUPERATO prima");
            EnergyObservedState st2;
            EnergyCheckParams vecchio = q;
            vecchio.trafficMargin = 0.0;
            checkEnergy(st2, S(10.0, 10.2, 80.00), vecchio);
            r = checkEnergy(st2, S(40.0, 40.2, 78.00), vecchio);
            verifica(esitoDi(r, "calo minimo") == Esito::SUPERATO,
                     "lo stesso calo di 2,00% con il controllo precedente: SUPERATO (conferma il confronto)");
        }
        // Piu' nodi nella rete: piu' messaggi da ritrasmettere, calo minimo piu' alto.
        {
            EnergyCheckParams doppio = q;
            doppio.networkNodes = 35;
            std::printf("        con 35 nodi invece di 18: calo minimo %.4f%% invece di %.4f%%\n",
                        doppio.minDrop(30), q.minDrop(30));
            verifica(doppio.minDrop(30) > q.minDrop(30),
                     "il calo minimo cresce con il numero di nodi della rete");
        }
    }

    std::printf("\n== Coerenza della misura (stesso timbro, valore diverso) ==\n");
    {
        EnergyObservedState st;
        checkEnergy(st, S(20.0, 20.2, 79.00), p);
        auto r = checkEnergy(st, S(20.0, 21.0, 85.00, false, "una voce di traccia"), p); stampa(r);
        verifica(esitoDi(r, "coerenza della misura") == Esito::VIOLATO,
                 "79,00% in un BANT e 85,00% in una traccia con lo stesso timbro: VIOLATO");
        r = checkEnergy(st, S(20.0, 21.5, 79.00, false, "una voce di traccia"), p);
        verifica(nessunaViolazione(r),
                 "lo stesso valore dichiarato due volte con lo stesso timbro: nessuna violazione");
        // il confronto vale anche fra due misure non consecutive
        checkEnergy(st, S(23.0, 23.2, 78.90), p);
        checkEnergy(st, S(26.0, 26.2, 78.80), p);
        r = checkEnergy(st, S(23.0, 27.0, 90.00, false, "una voce di traccia"), p); stampa(r);
        verifica(esitoDi(r, "coerenza della misura") == Esito::VIOLATO,
                 "contraddizione su un timbro di due misure prima: VIOLATO (storico dei timbri)");
    }

    std::printf("\n== Drone onesto simulato per 120 s (nessun falso positivo) ==\n");
    {
        // Consumo reale tra 2,12 e 2,62 mW (valori misurati dei droni onesti
        // che eseguono solo il protocollo), misure ogni 2,7 s, ritardo fino a
        // 3,5 s, calo minimo con il traffico di 18 nodi e coefficiente 0,5.
        EnergyCheckParams g = p;
        g.initialPct = 55.0;
        g.helloIntervalS = 5.0; g.networkNodes = 18; g.pRxW = 0.010; g.trafficMargin = 0.5;
        EnergyObservedState st;
        double e = 1.65, t = 0;
        int controlli = 0, violazioni = 0;
        for (int i = 0; i < 44; i++) {
            double potenza = 0.00212 + 0.0005 * ((i * 7) % 5) / 4.0;
            t += 2.7;
            e -= potenza * 2.7;
            double eta = 0.2 + 0.8 * (i % 4);   // eta' del dato all'arrivo: 0,2-2,6 s
            auto r = checkEnergy(st, S(t, t + eta, e / 3.0 * 100.0), g);
            for (auto& o : r) {
                if (o.esito != Esito::NON_APPLICABILE) controlli++;
                if (o.esito == Esito::VIOLATO) { violazioni++; std::printf("        %s: %s\n", o.controllo.c_str(), o.dettaglio.c_str()); }
            }
        }
        std::printf("        %d controlli eseguiti, %d violazioni\n", controlli, violazioni);
        verifica(controlli > 40 && violazioni == 0, "nessuna violazione per un drone onesto");
    }

    std::printf("\n%d test eseguiti, %d falliti\n", eseguiti, falliti);
    return falliti == 0 ? 0 : 1;
}

#endif // ANT2_TEST_STANDALONE
