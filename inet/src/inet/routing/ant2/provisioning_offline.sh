#!/bin/bash
# =============================================================================
# provisioning_offline.sh
#
# Genera tutte le chiavi necessarie per la modalita' di PROVISIONING OFFLINE
# del livello di sicurezza Ant2, e produce il frammento di configurazione .ini
# da incollare in omnetpp.ini.
#
# Va eseguito UNA VOLTA, dalla cartella inet/src/inet/routing/ant2/
# (quella che contiene le sottocartelle crypto/ e tools/).
#
# Produce:
#   keys/group.key                  chiave simmetrica di gruppo (16 byte)
#   keys/<indirizzo>_pub.bin        chiave pubblica di ogni nodo (32 byte)
#   keys/<indirizzo>_priv.bin       chiave privata di ogni nodo (64 byte)
#   roster/fleet_roster.txt         registro indirizzo -> chiave pubblica
#   security_offline.ini            righe da incollare in omnetpp.ini
# =============================================================================

set -e

# --- Mappa dei nodi: nome | indirizzo wlan | indirizzo X2 (alias, "-" se assente)
# Questi indirizzi sono quelli assegnati dal configuratore nello scenario
# simulations/sim_1 con numUe=10. Se cambi topologia o numero di UE, vanno
# riverificati (basta leggere le righe [SEC][AVVIO] di una run con
# useCentralAuthority=true).
NODI=(
  "adh0|10.0.0.241|10.0.0.133"
  "adh1|10.0.0.242|10.0.0.145"
  "adh2|10.0.0.243|10.0.0.157"
  "adh3|10.0.0.244|10.0.0.169"
  "adh4|10.0.0.245|10.0.0.181"
  "adh5|10.0.0.246|10.0.0.193"
  "adh6|10.0.0.247|10.0.0.205"
  "adh7|10.0.0.248|10.0.0.217"
  "adh8|10.0.0.249|10.0.0.229"
  "gat1|10.0.0.250|10.0.0.85"
  "gat2|10.0.0.251|-"
  "gat3|10.0.0.252|-"
)

# Converte 10.0.0.X nell'intero a 32 bit usato dal codice
ip2int() {
  local IFS=.
  read -r a b c d <<< "$1"
  echo $(( (a<<24) + (b<<16) + (c<<8) + d ))
}

echo "### 1) Compilazione degli strumenti ###"
g++ -std=c++14 -c crypto/ed25519/*.cc
g++ -std=c++14 -c tools/gen_node_keypair.c -o gen_node_keypair.o
g++ -std=c++14 -c tools/gen_group_key.c   -o gen_group_key.o
g++ -o gen_node_keypair gen_node_keypair.o fe.o ge.o sc.o sha512.o sign.o verify.o keypair.o add_scalar.o seed.o
g++ -o gen_group_key   gen_group_key.o   fe.o ge.o sc.o sha512.o sign.o verify.o keypair.o add_scalar.o seed.o
rm -f *.o
echo "    strumenti compilati."

echo "### 2) Generazione chiavi ###"
rm -rf keys roster
mkdir -p keys roster
: > roster/fleet_roster.txt

./gen_group_key keys/group.key > /dev/null
echo "    chiave di gruppo generata."

for riga in "${NODI[@]}"; do
  IFS='|' read -r nome wlan x2 <<< "$riga"
  wlan_int=$(ip2int "$wlan")

  ./gen_node_keypair "$wlan_int" keys roster/fleet_roster.txt > /dev/null

  # --- ALIAS ---
  # L'indirizzo X2 e' un SECONDO indirizzo dello STESSO nodo: deve comparire
  # nel roster con la STESSA chiave pubblica, non con una nuova coppia.
  # In modalita' autorita' centrale questo avviene a runtime
  # (registerOwnAlias); qui il roster e' statico, quindi va scritto adesso.
  if [ "$x2" != "-" ]; then
    x2_int=$(ip2int "$x2")
    pubkey_hex=$(grep "^${wlan_int} " roster/fleet_roster.txt | awk '{print $2}')
    echo "${x2_int} ${pubkey_hex}" >> roster/fleet_roster.txt
    echo "    $nome: $wlan (+ alias $x2)"
  else
    echo "    $nome: $wlan"
  fi
done

echo "### 3) Generazione del frammento .ini ###"
{
  echo "# --- Provisioning OFFLINE delle chiavi (generato da provisioning_offline.sh) ---"
  echo "# I percorsi sono relativi alla working directory della simulazione."
  echo "**.routing.useCentralAuthority = false"
  echo ""
  for riga in "${NODI[@]}"; do
    IFS='|' read -r nome wlan x2 <<< "$riga"
    wlan_int=$(ip2int "$wlan")
    case "$nome" in
      adh*) modulo="adh[${nome#adh}]" ;;
      *)    modulo="$nome" ;;
    esac
    echo "**.${modulo}.routing.groupKeyFile    = \"KEYDIR/group.key\""
    echo "**.${modulo}.routing.ownPubKeyFile   = \"KEYDIR/${wlan_int}_pub.bin\""
    echo "**.${modulo}.routing.ownPrivKeyFile  = \"KEYDIR/${wlan_int}_priv.bin\""
    echo "**.${modulo}.routing.fleetRosterFile = \"ROSTERDIR/fleet_roster.txt\""
    echo ""
  done
} > security_offline.ini

echo ""
echo "============================================================"
echo " FATTO."
echo ""
echo " Righe nel roster: $(wc -l < roster/fleet_roster.txt) (attese: 22 = 12 nodi + 10 alias)"
echo ""
echo " PROSSIMO PASSO: apri security_offline.ini e sostituisci"
echo "   KEYDIR     -> percorso della cartella keys/ visto dalla simulazione"
echo "   ROSTERDIR  -> percorso della cartella roster/ visto dalla simulazione"
echo " poi incolla il contenuto in omnetpp.ini, dentro [Config FastSecurityTest]."
echo "============================================================"
