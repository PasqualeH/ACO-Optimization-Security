// Ant2KeyAuthority.cc
#include "inet/routing/ant2/Ant2KeyAuthority.h"
#include <cstring>

extern "C" {
    #include "inet/routing/ant2/crypto/ed25519/ed25519.h"
}

namespace inet {
namespace ant2 {

Define_Module(Ant2KeyAuthority);

void Ant2KeyAuthority::initialize(int stage)
{
    // Non genera nulla qui: tutto avviene "on demand" nella prima chiamata a
    // provisionNode(), cosi' non serve preoccuparsi dell'ordine di
    // inizializzazione rispetto ai nodi Ant2 (che potrebbero girare prima o
    // dopo, a seconda dell'ordine di creazione dei moduli nella rete).
}

void Ant2KeyAuthority::provisionNode(uint32_t address,
                                      std::vector<uint8_t>& outGroupKey,
                                      std::vector<uint8_t>& outOwnPublicKey,
                                      std::vector<uint8_t>& outOwnPrivateKey)
{
    // 1) Chiave di gruppo: generata UNA sola volta, la prima volta che un
    // qualsiasi nodo la richiede; tutti i nodi successivi ricevono la stessa.
    if (!groupKeyGenerated) {
        unsigned char randomBytes[32];
        if (ed25519_create_seed(randomBytes) != 0)
            throw cRuntimeError("Ant2KeyAuthority: generazione della chiave di gruppo fallita");
        memcpy(groupKey, randomBytes, 16);
        groupKeyGenerated = true;
        EV_INFO << "Ant2KeyAuthority: chiave di gruppo generata" << endl;
    }
    outGroupKey.assign(groupKey, groupKey + 16);

    // 2) Coppia di chiavi Ed25519 per QUESTO indirizzo: generata solo se non
    // esiste ancora (un nodo che richiama provisionNode() piu' volte, ad
    // esempio dopo un riavvio simulato, riceve sempre la stessa identita').
    auto it = publicKeys.find(address);
    if (it == publicKeys.end()) {
        unsigned char seed[32], pub[32], priv[64];
        if (ed25519_create_seed(seed) != 0)
            throw cRuntimeError("Ant2KeyAuthority: generazione del seed fallita per l'indirizzo %u", address);
        ed25519_create_keypair(pub, priv, seed);

        publicKeys[address] = std::vector<uint8_t>(pub, pub + 32);
        privateKeys[address] = std::vector<uint8_t>(priv, priv + 64);

        EV_INFO << "Ant2KeyAuthority: nuova identita' generata per l'indirizzo " << address << endl;
    }

    outOwnPublicKey = publicKeys[address];
    outOwnPrivateKey = privateKeys[address];
}

void Ant2KeyAuthority::registerAlias(uint32_t alias, uint32_t primaryAddress)
{
    auto it = publicKeys.find(primaryAddress);
    if (it == publicKeys.end())
        throw cRuntimeError("Ant2KeyAuthority: registerAlias su indirizzo primario non ancora provisionato (%u)", primaryAddress);
    publicKeys[alias] = it->second;   // stessa identita': stessa chiave pubblica
    EV_INFO << "Ant2KeyAuthority: indirizzo " << alias << " registrato come alias di " << primaryAddress << endl;
}

bool Ant2KeyAuthority::lookupPublicKey(uint32_t address, std::vector<uint8_t>& outPublicKey) const
{
    auto it = publicKeys.find(address);
    if (it == publicKeys.end())
        return false;   // nodo mai visto dall'autorita': non fidato
    outPublicKey = it->second;
    return true;
}

} // namespace ant2
} // namespace inet
