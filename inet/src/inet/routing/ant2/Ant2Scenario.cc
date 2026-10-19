// =============================================================================
// Ant2Scenario.cc
//
// DIARIO DELLO SCENARIO (livello "essenziale")
//
// Scrive in un file di testo, in ordine di tempo simulato, che cosa succede a
// ogni drone durante la simulazione: avvio, invio dei FANT con i BANT ricevuti
// nel frattempo, richieste di aiuto, reclutamenti, spostamenti, soglie di
// energia, spegnimento, e un riepilogo finale per drone. Serve a osservare
// il comportamento reale del protocollo (per esempio: un drone reclutato torna
// disponibile? un drone scarico va a ricaricarsi e torna in gioco?).
//
// PRINCIPIO FONDAMENTALE: il diario OSSERVA, non modifica.
//   - non programma eventi e non usa numeri casuali;
//   - non modifica nessuna variabile del protocollo;
//   - NON interroga la mobilita' ne' la batteria in istanti "nuovi": in INET
//     sia getCurrentPosition() sia getEstimatedEnergyCapacity() aggiornano lo
//     stato interno quando vengono chiamate in un istante diverso dall'ultimo
//     aggiornamento, e quindi chiamarle in piu' cambierebbe gli arrotondamenti
//     della simulazione. Il diario usa solo valori che il protocollo ha GIA'
//     calcolato in quel momento (node_position, charge_status, ecc.).
// Per questo, con il diario attivo o spento, i risultati della simulazione
// sono identici byte per byte.
//
// Attivazione: parametro scenarioLog in Ant2.ned (default true).
// File prodotto: ant2_scenario_<config>_rN.log nella cartella dei risultati.
// =============================================================================

#include "inet/routing/ant2/Ant2.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <vector>

namespace inet {
namespace ant2 {

// -----------------------------------------------------------------------------
// Infrastruttura: file condiviso e registro indirizzo -> nome del drone
// -----------------------------------------------------------------------------

// Il registro e il file sono condivisi da tutti i nodi (static) e vanno
// riazzerati quando OMNeT++ passa alla run successiva nello stesso processo.
static int scenRunCorrente()
{
    return getEnvir()->getConfigEx()->getActiveRunNumber();
}

std::map<uint32_t, std::string>& Ant2::scenRegistroNomi()
{
    static std::map<uint32_t, std::string> registro;
    static int run = -1;
    if (run != scenRunCorrente()) {
        registro.clear();
        run = scenRunCorrente();
    }
    return registro;
}

std::ofstream& Ant2::scenarioLogFile()
{
    static std::ofstream log;
    static int runAperta = -1;
    if (runAperta != scenRunCorrente()) {
        if (log.is_open())
            log.close();
        log.open(nomeFileRun("ant2_scenario", ".log"), std::ios::trunc);
        runAperta = scenRunCorrente();
        log << "# =============================================================================\n"
            << "# DIARIO DELLO SCENARIO - protocollo Ant2\n"
            << "# Configurazione di sicurezza: " << descrizioneSicurezza() << "\n"
            << "# =============================================================================\n"
            << "# Una riga per evento:  <tempo simulato [s]>  <drone>  <EVENTO>  <descrizione>\n"
            << "#\n"
            << "# EVENTI\n"
            << "#   AVVIO        il drone si accende: cluster, indirizzi, ruolo, batteria\n"
            << "#   FANT         il drone invia il suo FANT periodico; la riga riporta anche\n"
            << "#                i BANT (stati degli altri droni) ricevuti dal FANT precedente\n"
            << "#   AIUTO        il drone chiede aiuto (banda >= 85% o energia < 15%): candidati,\n"
            << "#                punteggi e drone scelto\n"
            << "#   SOS          richiesta d'aiuto broadcast per energia bassa\n"
            << "#   SOS-RICEVUTO un drone riceve l'SOS di un altro\n"
            << "#   RECLUTATO    il drone accetta una richiesta d'aiuto rivolta a lui\n"
            << "#   RIFIUTA      richiesta rivolta a lui, ma non e' disponibile\n"
            << "#   SPOSTAMENTO  il drone reclutato viene spostato verso chi ha chiesto aiuto\n"
            << "#   ENERGIA      il drone supera una soglia di energia (15%, 10%)\n"
            << "#   RICARICA     viene chiamata moveUav_charge()\n"
            << "#   SPENTO / RIACCESO  il gestore dell'energia spegne/riaccende il nodo\n"
            << "#   FINE         riepilogo del drone a fine simulazione\n"
            << "#\n"
            << "# NOTE PER LA LETTURA\n"
            << "#   - energia in %: e' la percentuale CALCOLATA DAL PROTOCOLLO, cioe'\n"
            << "#     energia residua / nominalCapacity del modulo Ant2 (puo' superare 100%\n"
            << "#     se nominalCapacity e' minore della capacita' reale della batteria).\n"
            << "#   - posizione: e' l'ultima posizione registrata dal protocollo, aggiornata\n"
            << "#     ogni update_throughput_Interval (puo' essere vecchia di al massimo 1 s).\n"
            << "#   - 'disponibile' = allowed_accept_request (puo' essere reclutato);\n"
            << "#     'puo chiedere' = allowed_send_request (puo' chiedere aiuto).\n"
            << "#\n"
            << "# ESEMPI DI RICERCA\n"
            << "#   grep 'adh\\[6\\]' file.log          tutta la storia del drone adh[6]\n"
            << "#   grep -E 'RECLUTATO|RIFIUTA|AIUTO'  tutti i reclutamenti\n"
            << "#   grep -E 'ENERGIA|RICARICA|SPENTO'  tutto cio' che riguarda la batteria\n"
            << "#   grep FINE file.log                 il riepilogo finale per drone\n"
            << "# =============================================================================\n";
    }
    return log;
}

std::string Ant2::scenNome() const
{
    return getContainingNode(this)->getFullName();
}

std::string Ant2::scenNomeDi(const Ipv4Address& a)
{
    auto& reg = scenRegistroNomi();
    auto it = reg.find(a.getInt());
    if (it != reg.end())
        return it->second;
    return a.str();   // indirizzo non registrato: si stampa l'IP
}

std::string Ant2::scenNomeDi(const std::string& ipTestuale)
{
    return scenNomeDi(Ipv4Address(ipTestuale.c_str()));
}

void Ant2::scen(const char *evento, const std::string& testo)
{
    if (!scenarioLogEnabled)
        return;
    std::ofstream& log = scenarioLogFile();
    std::ostringstream riga;
    riga << std::fixed << std::setprecision(3) << std::setw(9) << simTime().dbl() << "  "
         << std::left << std::setw(13) << scenNome() << std::setw(13) << evento
         << std::right << testo << "\n";
    log << riga.str();
    log.flush();   // cosi' il file e' leggibile anche se la run si interrompe
}

static std::string fmtPos(const Coord& c)
{
    std::ostringstream s;
    s << std::fixed << std::setprecision(0) << "(" << c.x << ", " << c.y << ", " << c.z << ")";
    return s.str();
}

static const char *siNo(bool b) { return b ? "SI" : "NO"; }

// La posizione del protocollo (node_position) vale (0,0,0) finche' non viene
// aggiornata la prima volta da updateThroughput(): in quel caso si scrive n/d.
static std::string fmtPosProtocollo(const Coord& c)
{
    if (c.x == 0 && c.y == 0 && c.z == 0)
        return "n/d (non ancora aggiornata)";
    return fmtPos(c);
}

// Ordinamento "naturale" dei nomi: adh[2] prima di adh[10].
static bool nomeMinore(const std::string& a, const std::string& b)
{
    auto split = [](const std::string& s, std::string& pre, long& num) {
        size_t q = s.find('[');
        pre = s.substr(0, q);
        num = (q == std::string::npos) ? -1 : std::atol(s.c_str() + q + 1);
    };
    std::string pa, pb;
    long na, nb;
    split(a, pa, na);
    split(b, pb, nb);
    if (pa != pb)
        return pa < pb;
    if (na != nb)
        return na < nb;
    return a < b;
}

static std::string fmtT(simtime_t t)
{
    if (t < SIMTIME_ZERO)
        return "mai";
    std::ostringstream s;
    s << std::fixed << std::setprecision(3) << "t=" << t.dbl();
    return s.str();
}

// -----------------------------------------------------------------------------
// Eventi
// -----------------------------------------------------------------------------

void Ant2::scenAvvio()
{
    if (!scenarioLogEnabled)
        return;

    // Registra tutti gli indirizzi del drone, cosi' nelle righe degli altri
    // droni compare "adh[3]" invece di "10.0.0.244".
    auto& reg = scenRegistroNomi();
    std::ostringstream ind;
    for (size_t i = 0; i < wirelessInterfaces.size(); i++) {
        Ipv4Address a = wirelessInterfaces[i]->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
        reg[a.getInt()] = scenNome();
        ind << (i ? ", " : "") << a;
    }
    if (x2ppp_address != Ipv4Address::UNSPECIFIED_ADDRESS) {
        reg[x2ppp_address.getInt()] = scenNome();
        ind << " (+ X2 " << x2ppp_address << ")";
    }

    // Batteria: si leggono solo i PARAMETRI del modulo energyStorage (nessuna
    // interrogazione dello stato, che avrebbe effetti collaterali).
    std::ostringstream batt;
    cModule *storage = getContainingNode(this)->getSubmodule("energyStorage");
    try {
        if (storage && storage->hasPar("nominalCapacity")) {
            double nomJ = storage->par("nominalCapacity").doubleValueInUnit("J");
            double iniJ = storage->hasPar("initialCapacity")
                          ? storage->par("initialCapacity").doubleValueInUnit("J") : nomJ;
            if (std::isnan(iniJ))
                iniJ = nomJ;
            batt << std::setprecision(3) << "batteria " << nomJ << " J, carica iniziale " << iniJ
                 << " J; il protocollo usa nominalCapacity = " << nominalCapacity << " J, quindi parte da "
                 << std::fixed << std::setprecision(0) << (100.0 * iniJ / nominalCapacity) << "%";
        }
        else
            batt << "nessun modulo energyStorage";
    }
    catch (...) {
        batt << "parametri della batteria non leggibili";
    }

    scen_avvii++;
    std::ostringstream t;
    t << "cluster " << cluster_id << " | nome " << name << " | IP " << ind.str()
      << " | interfacce wireless " << wirelessInterfaces.size()
      << " | disponibile " << siNo(allowed_accept_request)
      << " | puo chiedere " << siNo(allowed_send_request)
      << " | " << batt.str();
    scen(scen_avvii == 1 ? "AVVIO" : "RIACCESO", t.str());
}

void Ant2::scenFant(double chargeStatus, double residualJ)
{
    if (!scenarioLogEnabled)
        return;
    scen_fant_round++;
    if (scen_first_fant < SIMTIME_ZERO)
        scen_first_fant = simTime();
    scen_last_fant = simTime();
    scen_last_charge = chargeStatus;

    // BANT ricevuti dal FANT precedente, raggruppati per mittente
    long totBant = 0;
    std::ostringstream da;
    bool primo = true;
    std::vector<std::pair<std::string, int>> mittenti(scen_bant_da.begin(), scen_bant_da.end());
    std::sort(mittenti.begin(), mittenti.end(),
              [](const std::pair<std::string, int>& x, const std::pair<std::string, int>& y) {
                  return nomeMinore(x.first, y.first);
              });
    for (const auto& kv : mittenti) {
        totBant += kv.second;
        da << (primo ? "" : ", ") << kv.first;
        if (kv.second > 1)
            da << " x" << kv.second;
        primo = false;
    }
    scen_bant_da.clear();

    int disp = 0;
    for (const auto& e : statusTable)
        if (e.allowed_accept_request)
            disp++;

    std::ostringstream t;
    t << "n." << scen_fant_round << " inviato | energia " << std::fixed << std::setprecision(0)
      << chargeStatus << "% (" << std::setprecision(3) << residualJ << " J)"
      << " | pos " << fmtPosProtocollo(node_position)
      << " | BANT ricevuti dal FANT precedente: " << totBant;
    if (totBant > 0)
        t << " da " << da.str();
    t << " | droni noti " << statusTable.size() << ", di cui disponibili " << disp
      << " | disponibile " << siNo(allowed_accept_request)
      << " | puo chiedere " << siNo(allowed_send_request);
    scen("FANT", t.str());
}

void Ant2::scenBant(const std::string& srcIp, double energiaMittente, bool mittenteDisponibile)
{
    if (!scenarioLogEnabled)
        return;
    (void)energiaMittente;
    (void)mittenteDisponibile;
    scen_bant_da[scenNomeDi(srcIp)]++;
    scen_bant_tot++;
}

void Ant2::scenAiuto(const std::vector<std::pair<std::string, double>>& candidati,
                     const std::string& scelto, double punteggio)
{
    if (!scenarioLogEnabled)
        return;
    scen_richieste++;

    std::ostringstream motivo;
    motivo << std::fixed << std::setprecision(2);
    if (max_band > 0 && node_throughput >= max_band * 0.85)
        motivo << "banda " << node_throughput << "/" << max_band << " Mbps (>= 85%)";
    if (node_energy < 15) {
        if (motivo.tellp() > 0) motivo << " e ";
        motivo << "energia " << std::setprecision(0) << node_energy << "% (< 15%)";
    }
    if (motivo.tellp() == 0)
        motivo << "nessuna soglia superata (chiamata di test)";

    // Ordinati per punteggio decrescente, solo per leggibilita'
    std::vector<std::pair<std::string, double>> ord = candidati;
    std::sort(ord.begin(), ord.end(),
              [](const std::pair<std::string, double>& a, const std::pair<std::string, double>& b) {
                  return a.second > b.second || (a.second == b.second && a.first < b.first);
              });

    // Droni noti ma NON disponibili: sono quelli che la formula ha escluso
    std::ostringstream esclusi;
    int nEsclusi = 0;
    for (const auto& e : statusTable)
        if (!e.allowed_accept_request) {
            esclusi << (nEsclusi ? ", " : "") << scenNomeDi(e.destinationAddress);
            nEsclusi++;
        }

    std::ostringstream t;
    t << "motivo: " << motivo.str() << " | candidati " << ord.size() << ":";
    t << std::fixed << std::setprecision(3);
    for (size_t i = 0; i < ord.size(); i++)
        t << (i ? "," : "") << " " << scenNomeDi(ord[i].first) << " " << ord[i].second;
    if (nEsclusi > 0)
        t << " | esclusi perche' non disponibili: " << esclusi.str();
    if (scelto.empty())
        t << " | NESSUN CANDIDATO: la richiesta non viene inviata";
    else
        t << " | scelto " << scenNomeDi(scelto) << " (punteggio " << punteggio << ")";
    scen("AIUTO", t.str());
}

void Ant2::scenAiutoNonPossibile()
{
    if (!scenarioLogEnabled)
        return;
    scen("AIUTO", "richiesta d'aiuto NON inviata: il drone non ha l'indirizzo X2 (x2ppp_address), "
                  "condizione richiesta da sendRecruiting()");
}

void Ant2::scenSos(double chargeStatus)
{
    if (!scenarioLogEnabled)
        return;
    scen_sos++;
    std::ostringstream t;
    t << "energia " << std::fixed << std::setprecision(0) << chargeStatus
      << "%: inviata richiesta broadcast con destinatario se stesso; da ora disponibile NO, puo chiedere NO";
    scen("SOS", t.str());
}

void Ant2::scenRichiestaRicevuta(const Ipv4Address& src, const Ipv4Address& dst, bool rivoltaAMe,
                                 bool disponibile, const Coord& coordRichiedente)
{
    if (!scenarioLogEnabled)
        return;
    if (rivoltaAMe) {
        std::ostringstream t;
        if (disponibile) {
            scen_reclutato++;
            t << "accetta la richiesta di " << scenNomeDi(src) << " (posizione " << fmtPos(coordRichiedente)
              << "): partira' tra 1 s | da ora disponibile NO";
            scen("RECLUTATO", t.str());
        }
        else {
            scen_rifiuti++;
            t << "la richiesta di " << scenNomeDi(src) << " era rivolta a lui, ma NON e' disponibile "
              << "(allowed_accept_request = false): la inoltra soltanto";
            scen("RIFIUTA", t.str());
        }
    }
    else if (src == dst) {
        // SOS per energia bassa: si registra una sola volta per mittente
        if (scen_sos_visti.insert(src.getInt()).second) {
            std::ostringstream t;
            t << "SOS di " << scenNomeDi(src) << " (posizione " << fmtPos(coordRichiedente)
              << "): non e' rivolto a questo drone (destinatario = mittente), nessuna azione, lo inoltra";
            scen("SOS-RICEVUTO", t.str());
        }
    }
}

void Ant2::scenSpostamento(const Coord& da, const Coord& a)
{
    if (!scenarioLogEnabled)
        return;
    std::ostringstream t;
    t << "moveUav(): spostato da " << fmtPos(da) << " a " << fmtPos(a)
      << " | dopo lo spostamento: disponibile NO, puo chiedere SI";
    scen("SPOSTAMENTO", t.str());
}

void Ant2::scenEnergia(double chargeStatus)
{
    if (!scenarioLogEnabled)
        return;
    scen_last_charge = chargeStatus;
    if (chargeStatus < scen_min_charge)
        scen_min_charge = chargeStatus;
    if (chargeStatus > scen_max_charge)
        scen_max_charge = chargeStatus;

    if (!scen_sotto15 && chargeStatus <= 15.0) {
        scen_sotto15 = true;
        scen_t15 = simTime();
        std::ostringstream t;
        t << "energia " << std::fixed << std::setprecision(0) << chargeStatus
          << "% (<= 15%): da ora handleMessageWhenUp() termina prima di elaborare i messaggi ricevuti "
             "e il timer dei FANT non viene piu' riprogrammato; restano attivi solo i timer di "
             "feromone e throughput";
        scen("ENERGIA", t.str());
    }
    if (!scen_sotto10 && chargeStatus <= 10.0) {
        scen_sotto10 = true;
        std::ostringstream t;
        t << "energia " << std::fixed << std::setprecision(0) << chargeStatus
          << "% (<= 10%): ramo 'batteria esaurita' (moveUav_charge() e cancellazione dei timer)";
        scen("ENERGIA", t.str());
    }
    if (scen_sotto15 && !scen_risalita && chargeStatus > 15.0) {
        scen_risalita = true;
        std::ostringstream t;
        t << "energia risalita a " << std::fixed << std::setprecision(0) << chargeStatus
          << "% (> 15%): il drone ha recuperato carica";
        scen("ENERGIA", t.str());
    }
}

void Ant2::scenRicarica()
{
    if (!scenarioLogEnabled)
        return;
    scen_ricariche++;
    if (scen_ricariche == 1) {
        scen_t_ricarica = simTime();
        scen("RICARICA", "moveUav_charge(): spostato alla stazione (1000, 1000, 50), disponibile NO. "
                         "La funzione NON ricarica la batteria e non riporta il drone in servizio "
                         "(le chiamate successive sono solo contate, vedi FINE)");
    }
}

void Ant2::scenStop()
{
    // Dopo finish() OMNeT++ arresta comunque tutti i nodi mentre smonta la
    // rete: quello non e' uno spegnimento dovuto alla batteria, non si registra.
    if (!scenarioLogEnabled || scen_finito)
        return;
    // Un nodo gia' spento e non riacceso non va registrato di nuovo (succede
    // quando la run si interrompe per errore e OMNeT++ smonta la rete).
    if (scen_spegnimenti >= scen_avvii)
        return;
    scen_spegnimenti++;
    std::ostringstream t;
    t << "il nodo viene spento (ultima energia letta dal protocollo: " << std::fixed
      << std::setprecision(0) << scen_last_charge << "%)";
    scen("SPENTO", t.str());
}

void Ant2::scenFine()
{
    if (!scenarioLogEnabled)
        return;
    scen_finito = true;
    std::ostringstream t;
    t << "energia ultima " << std::fixed << std::setprecision(0) << scen_last_charge << "%";
    if (scen_min_charge < 1e8)
        t << " (min " << scen_min_charge << "%, max " << scen_max_charge << "%)";
    t << " | FANT inviati " << scen_fant_round << " (primo " << fmtT(scen_first_fant)
      << ", ultimo " << fmtT(scen_last_fant) << ")"
      << " | BANT ricevuti " << scen_bant_tot
      << " | reclutato " << scen_reclutato << " volte, rifiutate " << scen_rifiuti
      << " | richieste d'aiuto " << scen_richieste << ", SOS " << scen_sos
      << " | moveUav_charge chiamata " << scen_ricariche << " volte"
      << (scen_ricariche ? " (prima " + fmtT(scen_t_ricarica) + ")" : std::string())
      << " | spento " << scen_spegnimenti << " volte"
      << " | a fine run: disponibile " << siNo(allowed_accept_request)
      << ", puo chiedere " << siNo(allowed_send_request)
      << ", pos " << fmtPosProtocollo(node_position);

    // Diagnosi automatica: le domande che interessano, con risposta esplicita.
    std::vector<std::string> note;
    simtime_t fine = simTime();
    if (scen_last_fant >= SIMTIME_ZERO && fine - scen_last_fant > 2 * helloInterval)
        note.push_back("ha smesso di inviare FANT a " + fmtT(scen_last_fant));
    if (scen_reclutato > 0 && !allowed_accept_request)
        note.push_back("dopo il reclutamento non e' MAI tornato disponibile");
    if (scen_sotto15 && !scen_risalita)
        note.push_back("sceso sotto il 15% a " + fmtT(scen_t15) + " e mai risalito (nessuna ricarica)");
    if (scen_ricariche > 0)
        note.push_back("mandato alla stazione di ricarica, ma non e' rientrato in servizio");
    if (!note.empty()) {
        t << " | NOTE:";
        for (size_t i = 0; i < note.size(); i++)
            t << (i ? ";" : "") << " " << note[i];
    }
    scen("FINE", t.str());
}

} // namespace ant2
} // namespace inet
