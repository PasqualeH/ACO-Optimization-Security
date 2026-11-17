#!/bin/bash
#
# misura_delta.sh - quante interazioni per nodo e per regola, e quale Delta
# serve per arrivare a 30 campioni.
#
# Uso, dalla cartella samples/sim_1:
#   bash misura_delta.sh                      usa TestFinaleOnesto, 120 s
#   bash misura_delta.sh TestFinaleAttacchi   un'altra prova
#   DURATA=300 bash misura_delta.sh           simulazione di altra durata
#
set -u

C=${1:-TestFinaleOnesto}
DIR=${DIR:-risultati_energia}
DURATA=${DURATA:-120}
CAMPIONI=${CAMPIONI:-30}

if [ ! -d "$DIR/$C" ]; then
    echo "cartella $DIR/$C non trovata"
    exit 1
fi

# nome del file di riepilogo -> etichetta della regola
REGOLE="energia:r1_energia posizione:r2_posizione disponibilita:r3_disponib falso_aiuto:r4_aiuto banda:r5_banda impronta:r0_impronta hop:r6_hop"

echo "============================================================================"
echo "  $C   (durata $DURATA s, obiettivo $CAMPIONI campioni)"
echo "============================================================================"
echo
printf "  %-14s %10s %8s %9s %11s %12s\n" regola controlli osserv "per_copp" "al_secondo" "Delta_per_$CAMPIONI"
echo "  ---------------------------------------------------------------------------"

for RL in $REGOLE; do
    FILE=${RL%%:*}
    NOME=${RL##*:}
    F=$(ls "$DIR/$C"/ant2_${FILE}_riepilogo_*.txt 2>/dev/null | head -1)
    [ -z "$F" ] && { printf "  %-14s %10s\n" "$NOME" "(assente)"; continue; }

    # In ogni riepilogo: $1 drone, $2 superati, $3 violati, ultimo campo = osservatori.
    grep -v '^#' "$F" | awk -v nome="$NOME" -v dur="$DURATA" -v camp="$CAMPIONI" '
    NF >= 4 {
        tot += $2 + $3;              # controlli conclusivi su questo drone
        oss = $NF;                   # quanti nodi lo hanno controllato
        if (oss > 0) { somma_oss += oss; righe++ }
    }
    END {
        if (righe == 0) { printf "  %-14s %10s\n", nome, "(vuoto)"; exit }
        oss_medi = somma_oss / righe;
        per_coppia = (oss_medi > 0) ? tot / righe / oss_medi : 0;
        al_sec = per_coppia / dur;
        if (al_sec > 0) delta = camp / al_sec; else delta = -1;
        printf "  %-14s %10d %8.1f %9.2f %11.4f ", nome, tot, oss_medi, per_coppia, al_sec;
        if (delta < 0)        printf "%12s\n", "mai";
        else if (delta < 300) printf "%10.0f s\n", delta;
        else                  printf "%9.1f min\n", delta / 60;
    }'
done

echo
echo "  Legenda:"
echo "    controlli   superati + violati su tutta la rete (i dubbi e i non applicabili"
echo "                restano fuori: nel rapporto W/T non entrano)"
echo "    osserv      quanti nodi, in media, controllano un singolo drone"
echo "    per_copp    controlli per coppia osservatore-drone in tutta la simulazione"
echo "    Delta       quanto deve durare la finestra perche' una coppia arrivi a $CAMPIONI campioni"
echo
echo "  Se ogni nodo calcola la fiducia con quello che vede LUI, vale la colonna"
echo "  Delta. Se invece i verdetti vengono messi in comune (per esempio tramite il"
echo "  bollettino della GCS), il campione si moltiplica per 'osserv' e il Delta si"
echo "  divide per lo stesso numero: la riga seguente lo mostra."
echo

printf "  %-14s %13s %13s\n" regola "Delta_locale" "Delta_in_comune"
echo "  ------------------------------------------"
for RL in $REGOLE; do
    FILE=${RL%%:*}
    NOME=${RL##*:}
    F=$(ls "$DIR/$C"/ant2_${FILE}_riepilogo_*.txt 2>/dev/null | head -1)
    [ -z "$F" ] && continue
    grep -v '^#' "$F" | awk -v nome="$NOME" -v dur="$DURATA" -v camp="$CAMPIONI" '
    NF >= 4 { tot += $2 + $3; somma_oss += $NF; righe++ }
    END {
        if (righe == 0 || tot == 0) exit;
        oss = somma_oss / righe;
        loc = camp / ((tot / righe / oss) / dur);
        com = camp / ((tot / righe) / dur);
        printf "  %-14s %10.0f s %10.0f s\n", nome, loc, com;
    }'
done

echo
echo "  --- distribuzione per drone (controlli conclusivi per coppia) ---"
for RL in $REGOLE; do
    FILE=${RL%%:*}
    NOME=${RL##*:}
    F=$(ls "$DIR/$C"/ant2_${FILE}_riepilogo_*.txt 2>/dev/null | head -1)
    [ -z "$F" ] && continue
    echo -n "  $NOME: "
    grep -v '^#' "$F" | awk '
    NF >= 4 && $NF > 0 { v[n++] = ($2 + $3) / $NF }
    END {
        if (n == 0) { print "(vuoto)"; exit }
        for (i = 0; i < n; i++) for (j = i+1; j < n; j++) if (v[j] < v[i]) { t = v[i]; v[i] = v[j]; v[j] = t }
        printf "minimo %.2f   mediana %.2f   massimo %.2f   (%d droni)\n", v[0], v[int(n/2)], v[n-1], n;
    }'
done
