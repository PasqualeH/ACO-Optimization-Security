// Ant2Crypto.cc
#include "Ant2Crypto.h"
#include <fstream>
#include <sstream>

extern "C" {
    #include "crypto/ascon/crypto_aead.h"
}
#include "crypto/ed25519/ed25519.h"
#include "inet/routing/ant2/Ant2KeyAuthority.h"

namespace inet {

static std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); i++)
        out[i] = static_cast<uint8_t>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
    return out;
}

void Ant2Crypto::loadGroupKey(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("Ant2Crypto: impossibile aprire la chiave di gruppo: " + path);
    f.read(reinterpret_cast<char*>(groupKey), GROUP_KEY_LEN);
    if (f.gcount() != GROUP_KEY_LEN)
        throw std::runtime_error("Ant2Crypto: chiave di gruppo di lunghezza errata in " + path);
}

void Ant2Crypto::loadOwnKeypair(const std::string& pubPath, const std::string& privPath) {
    std::ifstream fp(pubPath, std::ios::binary);
    if (!fp)
        throw std::runtime_error("Ant2Crypto: impossibile aprire la chiave pubblica: " + pubPath);
    fp.read(reinterpret_cast<char*>(ownPublicKey), PUBKEY_LEN);

    std::ifstream fs(privPath, std::ios::binary);
    if (!fs)
        throw std::runtime_error("Ant2Crypto: impossibile aprire la chiave privata: " + privPath);
    fs.read(reinterpret_cast<char*>(ownPrivateKey), PRIVKEY_LEN);
}

void Ant2Crypto::loadFleetRoster(const std::string& path) {
    std::ifstream f(path);
    if (!f)
        throw std::runtime_error("Ant2Crypto: impossibile aprire il fleet roster: " + path);
    uint32_t addr;
    std::string hex;
    while (f >> addr >> hex) {
        if (hex.size() != static_cast<size_t>(PUBKEY_LEN) * 2)
            throw std::runtime_error("Ant2Crypto: chiave pubblica di lunghezza errata nel roster per " + std::to_string(addr));
        fleetRoster[addr] = hexToBytes(hex);
    }
}

void Ant2Crypto::useCentralAuthority(ant2::Ant2KeyAuthority* authority, uint32_t myAddress) {
    liveAuthority = authority;
    myPrimaryAddress = myAddress;

    std::vector<uint8_t> gk, pub, priv;
    authority->provisionNode(myAddress, gk, pub, priv);

    if (gk.size() != GROUP_KEY_LEN || pub.size() != PUBKEY_LEN || priv.size() != PRIVKEY_LEN)
        throw std::runtime_error("Ant2Crypto: l'autorita' centrale ha restituito chiavi di lunghezza inattesa");

    memcpy(groupKey, gk.data(), GROUP_KEY_LEN);
    memcpy(ownPublicKey, pub.data(), PUBKEY_LEN);
    memcpy(ownPrivateKey, priv.data(), PRIVKEY_LEN);
}

void Ant2Crypto::deriveNonce(uint32_t srcAddress, uint32_t sequencenumber, MsgType type,
                              uint8_t out[NONCE_LEN]) const {
    memset(out, 0, NONCE_LEN);
    memcpy(out, &srcAddress, 4);
    memcpy(out + 4, &sequencenumber, 4);
    out[8] = 'A'; out[9] = 'N'; out[10] = 'T'; out[11] = '2';  // costante di dominio
    out[12] = static_cast<uint8_t>(type);
    // out[13..15] restano a zero: 16 byte totali, come richiesto da Ascon-AEAD128
}

bool Ant2Crypto::encrypt(const std::vector<uint8_t>& plaintext,
                          const std::vector<uint8_t>& aad,
                          const uint8_t nonce[NONCE_LEN],
                          std::vector<uint8_t>& outCiphertext,
                          uint8_t outTag[TAG_LEN]) const {
    std::vector<uint8_t> combined(plaintext.size() + TAG_LEN);
    unsigned long long clen = 0;
    int rc = crypto_aead_encrypt(combined.data(), &clen,
                                  plaintext.data(), plaintext.size(),
                                  aad.data(), aad.size(),
                                  nullptr, nonce, groupKey);
    if (rc != 0)
        return false;
    outCiphertext.assign(combined.begin(), combined.begin() + plaintext.size());
    memcpy(outTag, combined.data() + plaintext.size(), TAG_LEN);
    return true;
}

bool Ant2Crypto::decrypt(const std::vector<uint8_t>& ciphertext,
                          const uint8_t tag[TAG_LEN],
                          const std::vector<uint8_t>& aad,
                          const uint8_t nonce[NONCE_LEN],
                          std::vector<uint8_t>& outPlaintext) const {
    std::vector<uint8_t> combined(ciphertext.begin(), ciphertext.end());
    combined.insert(combined.end(), tag, tag + TAG_LEN);

    outPlaintext.resize(ciphertext.size());
    unsigned long long mlen = 0;
    int rc = crypto_aead_decrypt(outPlaintext.data(), &mlen, nullptr,
                                  combined.data(), combined.size(),
                                  aad.data(), aad.size(),
                                  nonce, groupKey);
    if (rc != 0)
        return false;   // tag non valido: pacchetto manomesso o non autentico
    outPlaintext.resize(mlen);
    return true;
}

void Ant2Crypto::sign(const std::vector<uint8_t>& msg, uint8_t outSig[SIG_LEN]) const {
    ed25519_sign(outSig, msg.data(), msg.size(), ownPublicKey, ownPrivateKey);
}

void Ant2Crypto::useRogueIdentity() {
    unsigned char seed[32];
    if (ed25519_create_seed(seed) != 0)
        throw std::runtime_error("Ant2Crypto: generazione dell'identita' rogue fallita");
    ed25519_create_keypair(ownPublicKey, ownPrivateKey, seed);
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

bool Ant2Crypto::verify(const std::vector<uint8_t>& msg, const uint8_t sig[SIG_LEN],
                         uint32_t srcAddress) const {
    if (liveAuthority != nullptr) {
        // Modalita' autorita' centrale: chiave pubblica chiesta in tempo reale.
        std::vector<uint8_t> pub;
        if (!liveAuthority->lookupPublicKey(srcAddress, pub))
            return false;   // mittente mai visto dall'autorita': non fidato
        return ed25519_verify(sig, msg.data(), msg.size(), pub.data()) == 1;
    }
    // Modalita' provisioning offline: tabella caricata da file una volta sola.
    auto it = fleetRoster.find(srcAddress);
    if (it == fleetRoster.end())
        return false;   // mittente non presente nel roster della flotta: non fidato
    return ed25519_verify(sig, msg.data(), msg.size(), it->second.data()) == 1;
}

bool Ant2Crypto::isKnownNode(uint32_t srcAddress) const {
    if (liveAuthority != nullptr) {
        std::vector<uint8_t> pub;
        return liveAuthority->lookupPublicKey(srcAddress, pub);
    }
    return fleetRoster.find(srcAddress) != fleetRoster.end();
}

} // namespace inet
