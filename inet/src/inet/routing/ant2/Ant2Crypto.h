// Ant2Crypto.h
//
// Wrapper C++ minimale che espone ad Ant2.cc le primitive di sicurezza:
//   - un algoritmo AEAD (confidenzialita' + integrita' del payload sensibile),
//     SCEGLIBILE a tempo di configurazione fra Ascon-AEAD128, AES-128/192/256-GCM,
//     ChaCha20-Poly1305, Xoodyak e TinyJAMBU-128. La scelta si fa dal file .ini,
//     senza ricompilare.
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

#include "inet/routing/ant2/Ant2Aead.h"
#include "inet/routing/ant2/Ant2Sign.h"

namespace inet {

namespace ant2 { class Ant2KeyAuthority; }  // forward declaration, vedi useCentralAuthority()

class Ant2Crypto {
  public:
    // La chiave di gruppo ha lunghezza diversa a seconda dell'AEAD scelto
    // (16 B per Ascon, AES-128, Xoodyak e TinyJAMBU-128; 24 B per AES-192;
    // 32 B per AES-256 e ChaCha20).
    // Il buffer e' dimensionato sul caso peggiore; la lunghezza realmente in uso
    // si legge con groupKeyLen().
    static const int MAX_GROUP_KEY_LEN = ant2aead::MAX_KEY_LEN;   // 32
    // Anche il nonce cambia (16 B per Ascon e Xoodyak, 12 B per GCM,
    // ChaCha20-Poly1305 e TinyJAMBU-128).
    // La costante resta 16 perche' e' il caso peggiore e perche' Ant2.cc la usa
    // per dimensionare i buffer sullo stack: i byte in eccesso restano a zero.
    static const int NONCE_LEN     = ant2aead::MAX_NONCE_LEN;     // 16
    // Il tag di autenticazione NON ha piu' lunghezza fissa: 16 B per tutti gli
    // AEAD tranne TinyJAMBU-128, che ne usa 8. MAX_TAG_LEN serve solo a
    // dimensionare i buffer; i byte da usare davvero si leggono con tagLen().
    // (La vecchia costante TAG_LEN = 16 e' stata eliminata apposta: cosi' ogni
    // punto che la usava ha dovuto essere rivisto, e nessuno resta a presumere 16.)
    static const int MAX_TAG_LEN   = ant2aead::MAX_TAG_LEN;       // 16
    // Le chiavi di firma hanno lunghezza diversa a seconda dell'algoritmo:
    //   Ed25519      pubblica 32 B, privata 64 B
    //   ECDSA P-256  pubblica 64 B, privata 32 B
    // I buffer sono dimensionati sul caso peggiore; le lunghezze realmente in
    // uso si leggono con pubKeyLen() e privKeyLen().
    static const int MAX_PUBKEY_LEN  = ant2sign::MAX_PUBKEY_LEN;   // 64
    static const int MAX_PRIVKEY_LEN = ant2sign::MAX_PRIVKEY_LEN;  // 64
    // La firma e' di 64 byte con ENTRAMBI gli algoritmi: il formato dei
    // messaggi non cambia al variare della scelta.
    static const int SIG_LEN         = ant2sign::SIG_LEN;          // 64

    // Identificano il tipo di messaggio nella derivazione del nonce,
    // cosi' un FANT e un BANT dello stesso nodo con lo stesso sequencenumber
    // non riusano mai lo stesso nonce (fondamentale per la sicurezza di un AEAD).
    enum MsgType : uint8_t { MSG_FANT = 1, MSG_BANT = 2, MSG_REQ = 3 };

    // --- Scelta dell'algoritmo AEAD ---
    // DA CHIAMARE PRIMA di qualunque caricamento di chiavi: determina quanti
    // byte di chiave di gruppo servono e quanto lungo sara' il nonce.
    // Se il nome non e' riconosciuto solleva un'eccezione: meglio fermarsi che
    // misurare un algoritmo diverso da quello che si crede di aver configurato.
    void setAeadAlgorithm(const std::string& name);

    // --- Scelta dell'algoritmo di firma ---
    // Anche questa DA CHIAMARE PRIMA del caricamento delle chiavi.
    void setSignatureAlgorithm(const std::string& name);

    ant2sign::Algorithm signatureAlgorithm() const { return sig; }
    const char *signatureName() const { return ant2sign::name(sig); }
    int pubKeyLen() const { return ant2sign::pubKeyLen(sig); }
    int privKeyLen() const { return ant2sign::privKeyLen(sig); }

    ant2aead::Algorithm aeadAlgorithm() const { return aead; }
    const char *aeadName() const { return ant2aead::name(aead); }
    int groupKeyLen() const { return ant2aead::keyLen(aead); }
    int nonceLen() const { return ant2aead::nonceLen(aead); }
    int tagLen() const { return ant2aead::tagLen(aead); }

    // --- Caricamento chiavi (da chiamare una volta in initialize(), per nodo) ---

    // File binario grezzo con la chiave di gruppo condivisa da tutta la flotta.
    // La lunghezza attesa dipende dall'AEAD scelto: vedi groupKeyLen().
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

    // Deriva un nonce, unico per (nodo mittente, sequencenumber, tipo messaggio).
    // Il buffer e' sempre di 16 byte; all'AEAD ne arrivano nonceLen() (16 o 12).
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
                 uint8_t outTag[MAX_TAG_LEN]) const;   // scrive tagLen() byte

    bool decrypt(const std::vector<uint8_t>& ciphertext,
                 const uint8_t tag[MAX_TAG_LEN],       // legge tagLen() byte
                 const std::vector<uint8_t>& aad,
                 const uint8_t nonce[NONCE_LEN],
                 std::vector<uint8_t>& outPlaintext) const;

    // Firma con la chiave privata del nodo locale.
    void sign(const std::vector<uint8_t>& msg, uint8_t outSig[SIG_LEN]) const;

    // Verifica la firma usando la chiave pubblica di srcAddress presa dal fleet roster.
    // Ritorna false anche se srcAddress non e' nel roster (nodo sconosciuto -> non fidato).
    bool verify(const std::vector<uint8_t>& msg, const uint8_t signature[SIG_LEN],
                uint32_t srcAddress) const;

    bool isKnownNode(uint32_t srcAddress) const;

  private:
    ant2aead::Algorithm aead = ant2aead::ASCON128;   // default: comportamento identico a prima
    uint8_t groupKey[MAX_GROUP_KEY_LEN] = {0};
    ant2sign::Algorithm sig = ant2sign::ED25519;   // default: comportamento identico a prima
    uint8_t ownPublicKey[MAX_PUBKEY_LEN] = {0};
    uint8_t ownPrivateKey[MAX_PRIVKEY_LEN] = {0};
    std::unordered_map<uint32_t, std::vector<uint8_t>> fleetRoster;

    // Se non nullptr, isKnownNode()/verify() interrogano questo modulo invece
    // della tabella fleetRoster caricata da file (modalita' "autorita' centrale").
    ant2::Ant2KeyAuthority *liveAuthority = nullptr;
    uint32_t myPrimaryAddress = 0;
};

} // namespace inet

#endif
