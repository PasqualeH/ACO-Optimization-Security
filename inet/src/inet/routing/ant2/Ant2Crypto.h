// Ant2Crypto.h
//
// Wrapper C++ minimale che espone ad Ant2.cc le due primitive scelte:
//   - Ascon-AEAD128 (lo standard NIST SP 800-232, discendente diretto di Ascon-128a)
//     per confidenzialita' + integrita' del payload sensibile
//   - Ed25519 per l'autenticazione: chi ha davvero generato il messaggio
//
// Non contiene crittografia "fatta in casa": si appoggia solo alle
// implementazioni di riferimento vendorizzate in crypto/ascon e crypto/ed25519.

#ifndef __INET_ANT2CRYPTO_H
#define __INET_ANT2CRYPTO_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <stdexcept>

namespace inet {

namespace ant2 { class Ant2KeyAuthority; }  // forward declaration, vedi useCentralAuthority()

class Ant2Crypto {
  public:
    static const int GROUP_KEY_LEN = 16;   // chiave simmetrica ASCON
    static const int NONCE_LEN     = 16;   // nonce ASCON (derivato, non trasmesso)
    static const int TAG_LEN       = 16;   // tag di autenticazione ASCON
    static const int PUBKEY_LEN    = 32;   // chiave pubblica Ed25519
    static const int PRIVKEY_LEN   = 64;   // chiave privata Ed25519 (formato esteso seed+pub)
    static const int SIG_LEN       = 64;   // firma Ed25519

    // Identificano il tipo di messaggio nella derivazione del nonce,
    // cosi' un FANT e un BANT dello stesso nodo con lo stesso sequencenumber
    // non riusano mai lo stesso nonce (fondamentale per la sicurezza di un AEAD).
    enum MsgType : uint8_t { MSG_FANT = 1, MSG_BANT = 2, MSG_REQ = 3 };

    // --- Caricamento chiavi (da chiamare una volta in initialize(), per nodo) ---

    // File binario di 16 byte grezzi: la chiave di gruppo condivisa da tutta la flotta.
    void loadGroupKey(const std::string& path);

    // File binari con la propria coppia di chiavi Ed25519 (32B pubblica, 64B privata).
    void loadOwnKeypair(const std::string& pubPath, const std::string& privPath);

    // "Fleet roster": tabella testuale indirizzo_ipv4_intero -> chiave pubblica (hex, 64 char).
    // Una riga per nodo, generata offline dallo script di provisioning.
    void loadFleetRoster(const std::string& path);

    // --- APPROCCIO ALTERNATIVO: autorita' centrale "in-simulazione" ---
    // Da chiamare AL POSTO di loadGroupKey/loadOwnKeypair/loadFleetRoster.
    // 'myAddress' e' l'indirizzo del nodo che chiama (se ne conosce direttamente
    // da questo momento in poi, non serve saperlo in anticipo). Da questo punto,
    // anche isKnownNode()/verify() interrogano l'autorita' in tempo reale invece
    // che una tabella caricata da file una volta sola.
    void useCentralAuthority(ant2::Ant2KeyAuthority* authority, uint32_t myAddress);

    // Dichiara che 'alias' e' un ulteriore indirizzo IP DELLO STESSO nodo
    // (es. l'interfaccia X2/PPP oltre alla wlan). Senza questa registrazione i
    // messaggi inviati usando il secondo indirizzo come srcAddress verrebbero
    // rifiutati dagli altri nodi come "mittente sconosciuto".
    // In modalita' provisioning offline non fa nulla: in quel caso il fleet
    // roster deve gia' contenere una riga anche per l'indirizzo alias,
    // associata alla stessa chiave pubblica del nodo.
    void registerOwnAlias(uint32_t alias);

    // --- SOLO PER I TEST DI SICUREZZA (nodo malevolo) ---
    // Sostituisce la coppia di chiavi Ed25519 del nodo con una generata al volo
    // e NON registrata presso l'autorita' / non presente nel fleet roster.
    // Il nodo continua a firmare i propri messaggi, ma con una chiave che
    // nessun altro riconosce: i suoi pacchetti verranno quindi rifiutati da
    // tutti i riceventi ("firma non valida"), mentre lui continuera' a
    // verificare correttamente quelli altrui.
    // Modella un drone compromesso/riprogrammato che tenta di iniettare
    // messaggi di routing senza possedere una identita' legittima.
    void useRogueIdentity();

    // --- Operazioni usate ad ogni invio/ricezione ---

    // Deriva un nonce a 16 byte, unico per (nodo mittente, sequencenumber, tipo messaggio).
    // Non viene mai trasmesso: chi riceve lo ricalcola da campi gia' presenti nel pacchetto.
    void deriveNonce(uint32_t srcAddress, uint32_t sequencenumber, MsgType type,
                      uint8_t out[NONCE_LEN]) const;

    // Cifra 'plaintext' (i campi sensibili: coordinate, energia, throughput, ...).
    // 'aad' sono i campi che restano in chiaro ma vanno comunque autenticati
    // (srcAddress, dstAddress, sequencenumber): l'AEAD garantisce che nessuno li alteri.
    bool encrypt(const std::vector<uint8_t>& plaintext,
                 const std::vector<uint8_t>& aad,
                 const uint8_t nonce[NONCE_LEN],
                 std::vector<uint8_t>& outCiphertext,
                 uint8_t outTag[TAG_LEN]) const;

    bool decrypt(const std::vector<uint8_t>& ciphertext,
                 const uint8_t tag[TAG_LEN],
                 const std::vector<uint8_t>& aad,
                 const uint8_t nonce[NONCE_LEN],
                 std::vector<uint8_t>& outPlaintext) const;

    // Firma con la chiave privata del nodo locale.
    void sign(const std::vector<uint8_t>& msg, uint8_t outSig[SIG_LEN]) const;

    // Verifica la firma usando la chiave pubblica di srcAddress presa dal fleet roster.
    // Ritorna false anche se srcAddress non e' nel roster (nodo sconosciuto -> non fidato).
    bool verify(const std::vector<uint8_t>& msg, const uint8_t sig[SIG_LEN],
                uint32_t srcAddress) const;

    bool isKnownNode(uint32_t srcAddress) const;

  private:
    uint8_t groupKey[GROUP_KEY_LEN] = {0};
    uint8_t ownPublicKey[PUBKEY_LEN] = {0};
    uint8_t ownPrivateKey[PRIVKEY_LEN] = {0};
    std::unordered_map<uint32_t, std::vector<uint8_t>> fleetRoster;

    // Se non nullptr, isKnownNode()/verify() interrogano questo modulo invece
    // della tabella fleetRoster caricata da file (modalita' "autorita' centrale").
    ant2::Ant2KeyAuthority *liveAuthority = nullptr;
    uint32_t myPrimaryAddress = 0;
};

} // namespace inet

#endif
