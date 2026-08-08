// Ant2KeyAuthority.h
//
// APPROCCIO ALTERNATIVO al provisioning offline (vedi Ant2Crypto::loadGroupKey /
// loadOwnKeypair / loadFleetRoster). Qui le chiavi non vengono generate da uno
// strumento esterno prima della run: le genera questo modulo, DENTRO la
// simulazione, la prima volta che un nodo le richiede ("provisioning lazy").
//
// Modello di fiducia diverso e da dichiarare esplicitamente: si assume
// l'esistenza di un'autorita' centrale fidata (l'operatore della flotta) che
// genera e distribuisce le chiavi -- analogo a un server di fleet-management
// che emette certificati ad ogni drone al momento del provisioning reale.
//
// Vantaggio pratico: essendo nello stesso processo, non serve conoscere in
// anticipo gli indirizzi IP assegnati dal configuratore (vedi discussione):
// ogni nodo, nel proprio initialize(), chiede le chiavi passando il PROPRIO
// indirizzo nel momento stesso in cui lo conosce.

#ifndef __INET_ANT2KEYAUTHORITY_H
#define __INET_ANT2KEYAUTHORITY_H

#include <omnetpp.h>
#include <cstdint>
#include <vector>
#include <unordered_map>

using namespace omnetpp;

namespace inet {
namespace ant2 {

class Ant2KeyAuthority : public cSimpleModule
{
  public:
    // Chiamato da ogni nodo nel proprio initialize(), passando il proprio
    // indirizzo. Se e' la prima volta che si vede questo indirizzo, l'autorita'
    // genera al volo una coppia di chiavi Ed25519 per quel nodo (e, se non
    // esiste ancora, anche la chiave di gruppo Ascon, condivisa da tutti).
    // Riempie i tre buffer di output con le chiavi in chiaro, pronte per essere
    // caricate in un Ant2Crypto locale al nodo chiamante.
    void provisionNode(uint32_t address,
                        std::vector<uint8_t>& outGroupKey,
                        std::vector<uint8_t>& outOwnPublicKey,
                        std::vector<uint8_t>& outOwnPrivateKey);

    // Chiamato da Ant2Crypto::verify() quando lavora in modalita' "autorita'
    // centrale": invece di consultare un roster caricato una volta da file,
    // chiede qui, in tempo reale, la chiave pubblica del mittente da verificare.
    bool lookupPublicKey(uint32_t address, std::vector<uint8_t>& outPublicKey) const;

    // Registra un indirizzo ALIAS come appartenente allo stesso nodo di
    // 'primaryAddress' (stessa identita', stessa chiave pubblica).
    // Serve perche' un nodo puo' avere piu' interfacce e quindi piu' indirizzi
    // IP (es. wlan verso la FANET e X2/PPP verso il proprio gNodeB): il
    // protocollo Ant2 invia messaggi usando l'uno o l'altro come srcAddress,
    // e senza questa mappatura i messaggi inviati con il secondo indirizzo
    // verrebbero scartati come provenienti da un mittente sconosciuto.
    void registerAlias(uint32_t alias, uint32_t primaryAddress);

  protected:
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return 1; }

  private:
    bool groupKeyGenerated = false;
    uint8_t groupKey[16] = {0};

    std::unordered_map<uint32_t, std::vector<uint8_t>> publicKeys;   // indirizzo -> chiave pubblica (32B)
    std::unordered_map<uint32_t, std::vector<uint8_t>> privateKeys;  // indirizzo -> chiave privata (64B)
};

} // namespace ant2
} // namespace inet

#endif
