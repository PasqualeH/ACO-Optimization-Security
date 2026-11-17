// Ant2Crypto.cc
#include "Ant2Crypto.h"
#include <fstream>
#include <sstream>

#include "inet/routing/ant2/Ant2Aead.h"
#include "inet/routing/ant2/Ant2Sign.h"
#include "crypto/ed25519/ed25519.h"
extern "C" {
#include "crypto/ed25519/sha512.h"
}
#include "inet/routing/ant2/Ant2KeyAuthority.h"

namespace inet {

static std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); i++)
        out[i] = static_cast<uint8_t>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
    return out;
}

void Ant2Crypto::setAeadAlgorithm(const std::string& name) {
    ant2aead::Algorithm parsed;
    if (!ant2aead::parseName(name, parsed))
        throw std::runtime_error("Ant2Crypto: algoritmo AEAD sconosciuto: '" + name +
            "'. Valori ammessi: ascon128, aes128gcm, aes192gcm, aes256gcm, chacha20poly1305, "
            "xoodyak, tinyjambu128");
    aead = parsed;
}

void Ant2Crypto::setSignatureAlgorithm(const std::string& name) {
    ant2sign::Algorithm parsed;
    if (!ant2sign::parseName(name, parsed))
        throw std::runtime_error("Ant2Crypto: algoritmo di firma sconosciuto: '" + name +
            "'. Valori ammessi: ed25519, ecdsap256");
    sig = parsed;
}

void Ant2Crypto::loadGroupKey(const std::string& path) {
    const int need = groupKeyLen();
    std::ifstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("Ant2Crypto: impossibile aprire la chiave di gruppo: " + path);
    f.read(reinterpret_cast<char*>(groupKey), need);
    if (f.gcount() != need)
        throw std::runtime_error("Ant2Crypto: la chiave di gruppo in " + path + " non ha i " +
            std::to_string(need) + " byte richiesti da " + aeadName());
}

void Ant2Crypto::loadOwnKeypair(const std::string& pubPath, const std::string& privPath) {
    std::ifstream fp(pubPath, std::ios::binary);
    if (!fp)
        throw std::runtime_error("Ant2Crypto: impossibile aprire la chiave pubblica: " + pubPath);
    fp.read(reinterpret_cast<char*>(ownPublicKey), pubKeyLen());

    std::ifstream fs(privPath, std::ios::binary);
    if (!fs)
        throw std::runtime_error("Ant2Crypto: impossibile aprire la chiave privata: " + privPath);
    fs.read(reinterpret_cast<char*>(ownPrivateKey), privKeyLen());
}

void Ant2Crypto::loadFleetRoster(const std::string& path) {
    std::ifstream f(path);
    if (!f)
        throw std::runtime_error("Ant2Crypto: impossibile aprire il fleet roster: " + path);
    uint32_t addr;
    std::string hex;
    while (f >> addr >> hex) {
        if (hex.size() != static_cast<size_t>(pubKeyLen()) * 2)
            throw std::runtime_error("Ant2Crypto: chiave pubblica di lunghezza errata nel roster per " + std::to_string(addr));
        fleetRoster[addr] = hexToBytes(hex);
    }
}

void Ant2Crypto::useCentralAuthority(ant2::Ant2KeyAuthority* authority, uint32_t myAddress) {
    liveAuthority = authority;
    myPrimaryAddress = myAddress;

    std::vector<uint8_t> gk, pub, priv;
    // La lunghezza della chiave di gruppo dipende dall'AEAD scelto: la si chiede
    // esplicitamente all'autorita', che genera sempre 32 byte casuali e ne
    // restituisce il prefisso richiesto (cosi' tutti i nodi ricevono la stessa
    // chiave, qualunque sia la lunghezza in uso).
    authority->provisionNode(myAddress, static_cast<size_t>(groupKeyLen()),
                             static_cast<int>(sig), gk, pub, priv);

    if (static_cast<int>(gk.size()) != groupKeyLen() ||
        static_cast<int>(pub.size()) != pubKeyLen() ||
        static_cast<int>(priv.size()) != privKeyLen())
        throw std::runtime_error("Ant2Crypto: l'autorita' centrale ha restituito chiavi di lunghezza inattesa");

    memcpy(groupKey, gk.data(), gk.size());
    memcpy(ownPublicKey, pub.data(), pub.size());
    memcpy(ownPrivateKey, priv.data(), priv.size());
}

void Ant2Crypto::deriveNonce(uint32_t srcAddress, uint32_t peerAddress, uint32_t sequencenumber,
                              MsgType type, uint8_t out[NONCE_LEN]) const {
    // La regola da rispettare e' che lo stesso nonce non venga MAI usato due
    // volte con la stessa chiave: se succede, chi intercetta puo' sovrapporre i
    // due testi cifrati e ricavare la differenza dei due testi in chiaro, che
    // nel nostro caso (posizione, energia, banda dello stesso drone a pochi
    // istanti di distanza) rivela quasi tutto. L'autenticita' non si perde,
    // perche' ogni messaggio e' anche firmato, ma la riservatezza si'.
    //
    // CORREZIONE: il nonce del BANT era derivato da (chi invia il BANT, numero
    // di sequenza del FANT a cui risponde, tipo). Quel numero di sequenza non
    // e' del mittente del BANT ma del nodo che aveva creato il FANT, e nodi
    // diversi usano gli stessi numeri di sequenza, perche' ogni nodo ha il
    // proprio contatore che parte da zero e cresce di uno ogni helloInterval.
    // Un drone che rispondeva al FANT numero 7 di A e al FANT numero 7 di B
    // usava quindi due volte lo stesso nonce, e succedeva una quindicina di
    // volte per ogni giro di FANT.
    //
    // Si aggiunge quindi 'peerAddress', cioe' l'indirizzo dell'altro nodo
    // coinvolto: per il BANT il nodo che aveva creato il FANT (campo
    // dstAddress), per il REQ il destinatario. Quell'indirizzo e' GIA' presente
    // in chiaro nel messaggio ed e' GIA' fra i campi autenticati, quindi la
    // correzione non aggiunge nemmeno un byte e chi riceve puo' ricalcolare il
    // nonce come prima. La quaterna (mittente, altro nodo, numero di sequenza
    // di quell'altro nodo, tipo) e' unica, perche' per un nodo fissato i suoi
    // numeri di sequenza non si ripetono.
    //
    // I quattro valori non vengono accostati uno dopo l'altro perche' non
    // starebbero nei 12 byte di nonce di AES-GCM, ChaCha20 e TinyJAMBU-128
    // (4+4+4+1 = 13): si usano invece i primi nonceLen() byte dell'impronta
    // SHA-512 dei quattro valori, con una costante di separazione di dominio.
    // SHA-512 e' quella gia' compilata nel progetto per la firma Ed25519,
    // quindi non si aggiunge nessuna libreria.
    uint8_t buf[4 + 4 + 4 + 4 + 1];
    memcpy(buf, "ANT2", 4);
    memcpy(buf + 4, &srcAddress, 4);
    memcpy(buf + 8, &peerAddress, 4);
    memcpy(buf + 12, &sequencenumber, 4);
    buf[16] = static_cast<uint8_t>(type);

    uint8_t digest[64];
    sha512(buf, sizeof(buf), digest);

    memset(out, 0, NONCE_LEN);
    memcpy(out, digest, nonceLen());
}

bool Ant2Crypto::encrypt(const std::vector<uint8_t>& plaintext,
                          const std::vector<uint8_t>& aad,
                          const uint8_t nonce[NONCE_LEN],
                          std::vector<uint8_t>& outCiphertext,
                          uint8_t outTag[MAX_TAG_LEN]) const {
    outCiphertext.resize(plaintext.size());
    return ant2aead::encrypt(aead, groupKey, nonce,
                             aad.data(), aad.size(),
                             plaintext.data(), plaintext.size(),
                             outCiphertext.data(), outTag);
}

bool Ant2Crypto::decrypt(const std::vector<uint8_t>& ciphertext,
                          const uint8_t tag[MAX_TAG_LEN],
                          const std::vector<uint8_t>& aad,
                          const uint8_t nonce[NONCE_LEN],
                          std::vector<uint8_t>& outPlaintext) const {
    outPlaintext.resize(ciphertext.size());
    if (!ant2aead::decrypt(aead, groupKey, nonce,
                           aad.data(), aad.size(),
                           ciphertext.data(), ciphertext.size(),
                           tag, outPlaintext.data())) {
        outPlaintext.clear();
        return false;   // tag non valido: pacchetto manomesso o non autentico
    }
    return true;
}

void Ant2Crypto::sign(const std::vector<uint8_t>& msg, uint8_t outSig[SIG_LEN]) const {
    ant2sign::sign(sig, ownPrivateKey, ownPublicKey, msg.data(), msg.size(), outSig);
}

void Ant2Crypto::useRogueIdentity() {
    unsigned char seed[32];
    if (ed25519_create_seed(seed) != 0)
        throw std::runtime_error("Ant2Crypto: generazione dell'identita' rogue fallita");
    if (!ant2sign::generateKeypair(sig, seed, ownPublicKey, ownPrivateKey))
        throw std::runtime_error("Ant2Crypto: generazione dell'identita' rogue fallita");
    // Nota: la chiave di gruppo Ascon resta quella legittima. E' voluto:
    // modella un nodo che era parte della flotta (quindi conosce il segreto
    // condiviso) ma la cui identita' individuale non e' piu' valida/riconosciuta.
    // E' proprio il caso che la sola cifratura di gruppo NON saprebbe rilevare
    // e che invece la firma per-nodo Ed25519 individua.
}

void Ant2Crypto::registerOwnAlias(uint32_t alias) {
    if (liveAuthority != nullptr)
        liveAuthority->registerAlias(alias, myPrimaryAddress);
    // In modalita' offline non c'e' nulla da fare qui: la corrispondenza
    // alias -> chiave pubblica deve essere gia' presente nel fleet roster.
}

// NB: il parametro si chiama 'signature' e non 'sig' perche' 'sig' e' ormai il
// nome del membro che contiene l'algoritmo di firma scelto.
bool Ant2Crypto::verify(const std::vector<uint8_t>& msg, const uint8_t signature[SIG_LEN],
                         uint32_t srcAddress) const {
    if (liveAuthority != nullptr) {
        // Modalita' autorita' centrale: chiave pubblica chiesta in tempo reale.
        std::vector<uint8_t> pub;
        if (!liveAuthority->lookupPublicKey(srcAddress, pub))
            return false;   // mittente mai visto dall'autorita': non fidato
        return ant2sign::verify(this->sig, pub.data(), msg.data(), msg.size(), signature);
    }
    // Modalita' provisioning offline: tabella caricata da file una volta sola.
    auto it = fleetRoster.find(srcAddress);
    if (it == fleetRoster.end())
        return false;   // mittente non presente nel roster della flotta: non fidato
    return ant2sign::verify(this->sig, it->second.data(), msg.data(), msg.size(), signature);
}

bool Ant2Crypto::isKnownNode(uint32_t srcAddress) const {
    if (liveAuthority != nullptr) {
        std::vector<uint8_t> pub;
        return liveAuthority->lookupPublicKey(srcAddress, pub);
    }
    return fleetRoster.find(srcAddress) != fleetRoster.end();
}

} // namespace inet
