// Ant2KeyAuthority.cc
#include "inet/routing/ant2/Ant2KeyAuthority.h"
#include <cstring>

#include "inet/routing/ant2/Ant2Sign.h"
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
                                      size_t groupKeyLen,
                                      int signAlg,
                                      std::vector<uint8_t>& outGroupKey,
                                      std::vector<uint8_t>& outOwnPublicKey,
                                      std::vector<uint8_t>& outOwnPrivateKey)
{
    if (groupKeyLen == 0 || groupKeyLen > sizeof(groupKey))
        throw cRuntimeError("Ant2KeyAuthority: lunghezza di chiave di gruppo non valida (%zu byte)", groupKeyLen);

    // 1) Chiave di gruppo: generata UNA sola volta, la prima volta che un
    // qualsiasi nodo la richiede; tutti i nodi successivi ricevono la stessa.
    if (!groupKeyGenerated) {
        unsigned char randomBytes[32];
        if (ed25519_create_seed(randomBytes) != 0)
            throw cRuntimeError("Ant2KeyAuthority: generazione della chiave di gruppo fallita");
        memcpy(groupKey, randomBytes, sizeof(groupKey));
        groupKeyGenerated = true;
        groupKeyLenInUse = groupKeyLen;
        signAlgInUse = signAlg;
        EV_INFO << "Ant2KeyAuthority: chiave di gruppo generata (" << groupKeyLen << " byte in uso)" << endl;
    }
    else if (signAlgInUse != signAlg) {
        throw cRuntimeError("Ant2KeyAuthority: il nodo con indirizzo %u chiede un algoritmo di firma "
                            "diverso da quello gia' in uso nella flotta. "
                            "Verificare che **.routing.signatureAlgorithm sia impostato allo stesso "
                            "valore per TUTTI i nodi.", address);
    }
    else if (groupKeyLenInUse != groupKeyLen) {
        // Tutti i nodi devono usare lo stesso algoritmo AEAD, altrimenti
        // userebbero chiavi diverse e nessuno riuscirebbe a decifrare.
        throw cRuntimeError("Ant2KeyAuthority: il nodo con indirizzo %u chiede una chiave di gruppo di %zu byte, "
                            "ma la flotta ne sta gia' usando una di %zu byte. "
                            "Verificare che **.routing.aeadAlgorithm sia impostato allo stesso valore per TUTTI i nodi.",
                            address, groupKeyLen, groupKeyLenInUse);
    }
    outGroupKey.assign(groupKey, groupKey + groupKeyLen);

    // 2) Coppia di chiavi individuale per QUESTO indirizzo: generata solo se non
    // esiste ancora (un nodo che richiama provisionNode() piu' volte, ad
    // esempio dopo un riavvio simulato, riceve sempre la stessa identita').
    // Il tipo di coppia dipende dall'algoritmo di firma configurato.
    auto it = publicKeys.find(address);
    if (it == publicKeys.end()) {
        ant2sign::Algorithm alg = static_cast<ant2sign::Algorithm>(signAlg);
        unsigned char seed[32];
        unsigned char pub[ant2sign::MAX_PUBKEY_LEN] = {0};
        unsigned char priv[ant2sign::MAX_PRIVKEY_LEN] = {0};
        if (ed25519_create_seed(seed) != 0)
            throw cRuntimeError("Ant2KeyAuthority: generazione del seed fallita per l'indirizzo %u", address);
        if (!ant2sign::generateKeypair(alg, seed, pub, priv))
            throw cRuntimeError("Ant2KeyAuthority: generazione della coppia di chiavi fallita per l'indirizzo %u", address);

        publicKeys[address]  = std::vector<uint8_t>(pub,  pub  + ant2sign::pubKeyLen(alg));
        privateKeys[address] = std::vector<uint8_t>(priv, priv + ant2sign::privKeyLen(alg));

        EV_INFO << "Ant2KeyAuthority: nuova identita' " << ant2sign::name(alg)
                << " generata per l'indirizzo " << address << endl;
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
