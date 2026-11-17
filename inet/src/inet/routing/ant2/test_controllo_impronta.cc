//
// test_controllo_impronta.cc
//
// Test automatici della regola 0 della metrica di trust (coerenza fra canali).
// Verificano la logica pura di Ant2DigestCheck.h, senza OMNeT++, senza INET e
// senza la libreria crittografica: l'impronta qui e' un semplice numero, come
// nel modulo, perche' quello che si vuole provare e' la macchina a stati delle
// letture e la contabilita' dell'annullamento, non SHA-512.
//
// Compilazione ed esecuzione, dalla cartella radice del progetto:
//   g++ -std=c++17 -DANT2_TEST_STANDALONE -I inet/src \
//       inet/src/inet/routing/ant2/test_controllo_impronta.cc -o test_controllo_impronta
//   ./test_controllo_impronta
//
// Il corpo e' racchiuso in ANT2_TEST_STANDALONE perche' il makefile di INET
// compila tutti i .cc sotto src dentro libINET: senza questa protezione il
// main() di questo file finirebbe nella libreria e il collegamento fallirebbe.
#ifdef ANT2_TEST_STANDALONE

#include <cstdio>

#include "inet/routing/ant2/Ant2DigestCheck.h"

using namespace ant2digest;

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

static void stampa(const std::vector<DigestOutcome>& r)
{
    for (auto& o : r)
        std::printf("        %s  %s  %s\n", o.controllo.c_str(), esitoStr(o.esito), o.dettaglio.c_str());
}

static Esito esitoDi(const std::vector<DigestOutcome>& r)
{
    return r.empty() ? Esito::NON_APPLICABILE : r[0].esito;
}

static bool vuoto(const std::vector<DigestOutcome>& r) { return r.empty(); }

int main()
{
    DigestCheckParams p;
    const uint64_t IMPRONTA_A = 0x1122334455667788ULL;
    const uint64_t IMPRONTA_B = 0x99aabbccddeeff00ULL;

    std::printf("Regola 0: coerenza fra canali (equivocazione)\n\n");

    std::printf("== Caso onesto: il drone dichiara la stessa cosa a tutti ==\n");
    {
        DigestObservedState st;
        registraMisura(st, 10.0, IMPRONTA_A, p);
        auto r = checkDigest(st, 10.0, IMPRONTA_A, Fonte::TRACCIA, p); stampa(r);
        verifica(esitoDi(r) == Esito::SUPERATO, "impronte uguali: SUPERATO");
        verifica(st.confermate == 1 && st.contraddette == 0, "la lettura risulta confermata");
    }
    {
        // La GCS ripubblica la stessa impronta in piu' bollettini per resistere
        // alla perdita: i contatori non devono gonfiarsi.
        DigestObservedState st;
        registraMisura(st, 10.0, IMPRONTA_A, p);
        checkDigest(st, 10.0, IMPRONTA_A, Fonte::TRACCIA, p);
        auto r = checkDigest(st, 10.0, IMPRONTA_A, Fonte::TRACCIA, p);
        verifica(vuoto(r) && st.superati == 1, "impronta ripubblicata: nessun esito nuovo");
    }
    {
        DigestObservedState st;
        registraMisura(st, 10.0, IMPRONTA_A, p);
        auto r = checkDigest(st, 10.0, IMPRONTA_A, Fonte::BANT, p);
        verifica(esitoDi(r) == Esito::SUPERATO, "stessa cosa anche con impronta da un BANT della GCS");
    }

    std::printf("\n== Equivocazione: valori diversi per la stessa lettura ==\n");
    {
        DigestObservedState st;
        registraMisura(st, 10.0, IMPRONTA_A, p);
        auto r = checkDigest(st, 10.0, IMPRONTA_B, Fonte::TRACCIA, p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO, "impronte diverse: VIOLATO certo");
        verifica(st.contraddette == 1, "la lettura risulta contraddetta");
    }
    {
        // Lo stesso osservatore riceve due messaggi con lo stesso timbro e
        // valori diversi: equivocazione colta senza nessun aiuto della GCS.
        DigestObservedState st;
        registraMisura(st, 10.0, IMPRONTA_A, p);
        auto r = registraMisura(st, 10.0, IMPRONTA_B, p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO, "due messaggi locali discordi: VIOLATO senza la GCS");
        verifica(st.violatiLocali == 1, "la violazione e' contata come locale");
    }

    std::printf("\n== Copertura: la GCS pubblica letture che il nodo non ha ==\n");
    {
        DigestObservedState st;
        registraMisura(st, 10.0, IMPRONTA_A, p);
        auto r = checkDigest(st, 25.0, IMPRONTA_B, Fonte::TRACCIA, p); stampa(r);
        verifica(esitoDi(r) == Esito::NON_APPLICABILE, "timbro mai visto: NON_APPLICABILE, non violazione");
        verifica(st.violati == 0 && st.nonApplicabili == 1, "contato fra i non applicabili");
    }
    {
        DigestObservedState st;
        auto r = registraMisura(st, -1.0, IMPRONTA_A, p);
        verifica(vuoto(r) && st.storico.empty(), "misura mai eseguita (timbro negativo): ignorata");
    }

    std::printf("\n== Annullamento degli esiti derivati da una lettura falsificata ==\n");
    {
        DigestObservedState st;
        registraMisura(st, 10.0, IMPRONTA_A, p);
        annotaEsiti(st, 10.0, 4, 0, 1, p);     // le regole 1-5 avevano dato 4 superati e 1 dubbio
        auto r = checkDigest(st, 10.0, IMPRONTA_B, Fonte::TRACCIA, p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO, "lettura contraddetta: VIOLATO");
        verifica(r[0].annulla && r[0].annullaSuperati == 4 && r[0].annullaDubbi == 1,
                 "il chiamante riceve l'ordine di togliere 4 superati e 1 dubbio");
        verifica(st.annullatiSuperati == 4 && st.annullatiDubbi == 1, "annullamenti contabilizzati");
    }
    {
        // L'annullamento non puo' avvantaggiare l'attaccante: se le regole 1-5
        // avevano gia' trovato una violazione, quella viene tolta ma al suo
        // posto resta la violazione certa della regola 0.
        DigestObservedState st;
        registraMisura(st, 10.0, IMPRONTA_A, p);
        annotaEsiti(st, 10.0, 0, 3, 0, p);
        auto r = checkDigest(st, 10.0, IMPRONTA_B, Fonte::TRACCIA, p);
        verifica(r[0].annullaViolati == 3 && st.violati == 1,
                 "3 violazioni annullate, ma resta la violazione certa della regola 0");
    }
    {
        // Una lettura confermata non viene mai annullata.
        DigestObservedState st;
        registraMisura(st, 10.0, IMPRONTA_A, p);
        annotaEsiti(st, 10.0, 4, 0, 0, p);
        checkDigest(st, 10.0, IMPRONTA_A, Fonte::TRACCIA, p);
        verifica(st.annullatiSuperati == 0, "lettura confermata: nessun annullamento");
    }
    {
        // Annullamento una volta sola, anche se la smentita arriva due volte.
        DigestObservedState st;
        registraMisura(st, 10.0, IMPRONTA_A, p);
        annotaEsiti(st, 10.0, 2, 0, 0, p);
        checkDigest(st, 10.0, IMPRONTA_B, Fonte::TRACCIA, p);
        registraMisura(st, 10.0, IMPRONTA_B, p);
        verifica(st.annullatiSuperati == 2, "annullamento non ripetuto");
    }

    std::printf("\n== Storico e ordine di arrivo ==\n");
    {
        // L'impronta della GCS puo' arrivare prima del BANT: in quel caso il
        // confronto non e' applicabile ora, e scattera' quando il BANT arriva.
        DigestObservedState st;
        auto r = checkDigest(st, 10.0, IMPRONTA_A, Fonte::TRACCIA, p);
        verifica(esitoDi(r) == Esito::NON_APPLICABILE, "impronta prima del BANT: non applicabile per ora");
        auto r2 = registraMisura(st, 10.0, IMPRONTA_A, p); stampa(r2);
        verifica(esitoDi(r2) == Esito::SUPERATO,
                 "all'arrivo del BANT il confronto scatta sull'impronta tenuta da parte");
        verifica(st.nonApplicabili == 0, "il non applicabile viene ritirato: la copertura c'era");
    }
    {
        // Lo stesso, ma l'impronta arrivata per prima smentisce il BANT.
        DigestObservedState st;
        checkDigest(st, 10.0, IMPRONTA_B, Fonte::BANT, p);
        auto r = registraMisura(st, 10.0, IMPRONTA_A, p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO,
                 "impronta arrivata prima e discorde: VIOLATO all'arrivo del BANT");
    }
    {
        // Un'impronta tenuta da parte non viene riusata due volte.
        DigestObservedState st;
        checkDigest(st, 10.0, IMPRONTA_A, Fonte::TRACCIA, p);
        registraMisura(st, 10.0, IMPRONTA_A, p);
        auto r = registraMisura(st, 10.0, IMPRONTA_A, p);
        verifica(vuoto(r) && st.superati == 1, "l'impronta in attesa si consuma una volta sola");
    }
    {
        DigestObservedState st;
        for (int i = 0; i < 20; i++)
            registraMisura(st, 1.0 + i, IMPRONTA_A + i, p);
        verifica(st.storico.size() == STORICO_IMPRONTE, "lo storico non cresce oltre il limite");
        verifica(cercaMisura(st, 20.0, p) != nullptr, "la lettura piu' recente e' in memoria");
        verifica(cercaMisura(st, 1.0, p) == nullptr, "la piu' vecchia e' stata dimenticata");
        auto r = checkDigest(st, 1.0, IMPRONTA_A, Fonte::TRACCIA, p);
        verifica(esitoDi(r) == Esito::NON_APPLICABILE,
                 "impronta di una lettura troppo vecchia: non applicabile, non violazione");
    }
    {
        DigestObservedState st;
        registraMisura(st, 10.0, IMPRONTA_A, p);
        verifica(nonVerificate(st) == 1, "una lettura in attesa di verifica");
        checkDigest(st, 10.0, IMPRONTA_A, Fonte::TRACCIA, p);
        verifica(nonVerificate(st) == 0, "dopo la conferma non ce ne sono piu'");
    }

    std::printf("\n== Drone onesto per 50 letture (nessun falso positivo) ==\n");
    {
        DigestObservedState st;
        double t = 0;
        for (int i = 0; i < 50; i++) {
            t += 2.4;
            uint64_t imp = IMPRONTA_A + (uint64_t)i * 0x1000001ULL;
            registraMisura(st, t, imp, p);
            annotaEsiti(st, t, 5, 0, 0, p);
            // la GCS pubblica la stessa impronta, come fa un drone onesto
            checkDigest(st, t, imp, Fonte::TRACCIA, p);
        }
        verifica(st.violati == 0, "50 letture coerenti: nessuna violazione");
        verifica(st.confermate == 50, "tutte confermate");
        verifica(st.annullatiSuperati == 0, "nessun esito annullato");
    }
    {
        // Caso realistico: la GCS conosce solo una lettura su due (sovrapposizione
        // parziale fra i due canali). Nessun falso positivo, e i non applicabili
        // misurano la copertura.
        DigestObservedState st;
        double t = 0;
        for (int i = 0; i < 40; i++) {
            t += 2.4;
            uint64_t imp = IMPRONTA_B + (uint64_t)i;
            registraMisura(st, t, imp, p);
            if (i % 2 == 0)
                checkDigest(st, t, imp, Fonte::BANT, p);
        }
        verifica(st.violati == 0, "copertura parziale: nessun falso positivo");
        verifica(st.superati == 20, "verificata meta' delle letture");
    }

    std::printf("\n== La GCS pubblica due impronte discordi della stessa lettura ==\n");
    {
        // E' il caso dell'attaccante che mente nei BANT e dice il vero nelle
        // tracce: la GCS riceve entrambe le dichiarazioni e le pubblica
        // entrambe. La prova e' completa dentro il bollettino.
        DigestObservedState st;
        auto r = segnalaContesa(st, 10.0, IMPRONTA_A, IMPRONTA_B,
                                Fonte::BANT, Fonte::TRACCIA, p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO,
                 "due impronte discordi nel bollettino: VIOLATO anche senza copia propria");
        verifica(st.contraddette == 1, "la lettura risulta contraddetta");
    }
    {
        // Ripubblicata nei bollettini successivi: non si conta due volte.
        DigestObservedState st;
        segnalaContesa(st, 10.0, IMPRONTA_A, IMPRONTA_B, Fonte::BANT, Fonte::TRACCIA, p);
        auto r = segnalaContesa(st, 10.0, IMPRONTA_A, IMPRONTA_B, Fonte::BANT, Fonte::TRACCIA, p);
        verifica(vuoto(r) && st.violati == 1, "contesa ripubblicata: contata una volta sola");
    }
    {
        // Il drone ha la propria copia: gli esiti che ne aveva tratto le altre
        // regole vengono annullati.
        DigestObservedState st;
        registraMisura(st, 10.0, IMPRONTA_A, p);
        annotaEsiti(st, 10.0, 5, 0, 2, p);
        auto r = segnalaContesa(st, 10.0, IMPRONTA_A, IMPRONTA_B,
                                Fonte::BANT, Fonte::TRACCIA, p);
        verifica(r[0].annulla && r[0].annullaSuperati == 5 && r[0].annullaDubbi == 2,
                 "contesa con copia propria: gli esiti delle altre regole vengono annullati");
    }
    {
        // Se il messaggio arriva DOPO che la contesa e' stata accertata, non si
        // conta una seconda violazione.
        DigestObservedState st;
        segnalaContesa(st, 10.0, IMPRONTA_A, IMPRONTA_B, Fonte::BANT, Fonte::TRACCIA, p);
        auto r = registraMisura(st, 10.0, IMPRONTA_B, p);
        verifica(vuoto(r) && st.violati == 1, "messaggio arrivato dopo la contesa: non ricontato");
    }
    {
        DigestObservedState st;
        auto r = segnalaContesa(st, 10.0, IMPRONTA_A, IMPRONTA_A,
                                Fonte::BANT, Fonte::TRACCIA, p);
        verifica(vuoto(r), "due impronte uguali: nessuna contesa");
    }

    std::printf("\n== L'allerta viene ripetuta: la bugia si conta una volta sola ==\n");
    {
        // La GCS ripubblica l'allerta parecchie volte perche' arrivi a tutti, e
        // nel frattempo lo storico (otto letture) ha gia' dimenticato quella
        // contestata. Senza una memoria piu' lunga la stessa bugia verrebbe
        // contata una decina di volte.
        DigestObservedState st;
        segnalaContesa(st, 10.0, IMPRONTA_A, IMPRONTA_B, Fonte::BANT, Fonte::TRACCIA, p);
        for (int i = 0; i < 20; i++)
            registraMisura(st, 100.0 + i, IMPRONTA_A + i, p);   // sfratta lo storico
        verifica(cercaMisura(st, 10.0, p) == nullptr, "lo storico ha dimenticato la lettura");
        auto r = segnalaContesa(st, 10.0, IMPRONTA_A, IMPRONTA_B, Fonte::BANT, Fonte::TRACCIA, p);
        verifica(vuoto(r) && st.violati == 1,
                 "allerta ripetuta dopo lo sfratto: contata ancora una volta sola");
        verifica(giaContesa(st, 10.0, p), "la lettura resta nella memoria delle contese");
    }
    {
        // Anche la contesa colta localmente entra nella memoria lunga.
        DigestObservedState st;
        registraMisura(st, 10.0, IMPRONTA_A, p);
        registraMisura(st, 10.0, IMPRONTA_B, p);
        for (int i = 0; i < 20; i++)
            registraMisura(st, 100.0 + i, IMPRONTA_A + i, p);
        auto r = segnalaContesa(st, 10.0, IMPRONTA_A, IMPRONTA_B, Fonte::BANT, Fonte::TRACCIA, p);
        verifica(vuoto(r) && st.violati == 1,
                 "contesa locale poi confermata dalla GCS: una violazione sola");
    }

    std::printf("\n== Formato del bollettino (sezioni) ==\n");
    {
        using namespace ant2digest::wire;
        std::vector<RecordImpronta> imp(3);
        imp[0].nodo = 0x0A000001; imp[0].timbro = 12.345; imp[0].impronta = IMPRONTA_A; imp[0].fonte = 1;
        imp[1].nodo = 0x0A000002; imp[1].timbro = 15.000; imp[1].impronta = IMPRONTA_B; imp[1].fonte = 2;
        imp[2].nodo = 0x0A000003; imp[2].timbro = 17.750; imp[2].impronta = 7;          imp[2].fonte = 1;
        std::vector<RecordReq> req(1);
        req[0].mittente = 0x0A000004; req[0].destinatario = 0x0A000008;
        req[0].x = 100; req[0].y = 200; req[0].z = 50; req[0].seq = 9; req[0].istante = 11.865;

        std::vector<uint8_t> v;
        scriviSezioneImpronte(v, imp);
        scriviSezioneReq(v, req);
        std::printf("        bollettino di %zu byte: 3 impronte + 1 REQ\n", v.size());
        verifica(v.size() == 2 * LEN_INTESTAZIONE_SEZIONE + 3 * LEN_IMPRONTA + LEN_REQ,
                 "lunghezza del bollettino come previsto");

        std::vector<RecordImpronta> imp2;
        std::vector<RecordReq> req2;
        verifica(leggiBollettino(v, imp2, req2), "il bollettino si rilegge");
        verifica(imp2.size() == 3 && req2.size() == 1, "tutte le righe recuperate");
        verifica(imp2[1].nodo == imp[1].nodo && imp2[1].timbro == imp[1].timbro
                 && imp2[1].impronta == imp[1].impronta && imp2[1].fonte == imp[1].fonte,
                 "i campi di un'impronta tornano identici");
        verifica(req2[0].destinatario == req[0].destinatario && req2[0].istante == req[0].istante
                 && req2[0].x == req[0].x,
                 "i campi di un REQ tornano identici");
    }
    {
        using namespace ant2digest::wire;
        std::vector<uint8_t> v;
        std::vector<RecordImpronta> imp;
        std::vector<RecordReq> req;
        verifica(leggiBollettino(v, imp, req) && imp.empty() && req.empty(),
                 "bollettino vuoto: letto senza errori");
        std::vector<uint8_t> rotto = { 1, 10, 0, 1, 2, 3 };   // dichiara 10 impronte, non ce ne sono
        verifica(!leggiBollettino(rotto, imp, req), "bollettino malformato: rifiutato");
        std::vector<uint8_t> futuro;
        scriviSezioneImpronte(futuro, std::vector<RecordImpronta>(1));
        futuro.push_back(99); futuro.push_back(1); futuro.push_back(0);   // sezione di tipo ignoto
        verifica(leggiBollettino(futuro, imp, req) && imp.size() == 1,
                 "sezione di tipo sconosciuto: le sezioni note restano leggibili");
    }

    std::printf("\n%d test eseguiti, %d falliti\n", eseguiti, falliti);
    return falliti == 0 ? 0 : 1;
}

#endif // ANT2_TEST_STANDALONE
