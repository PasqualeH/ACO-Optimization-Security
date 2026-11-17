#!/bin/bash
#
# riepilogo_finale.sh - matrice regole/nodo e reclutamenti delle prove finali.
#
# Uso, dalla cartella samples/sim_1:
#   bash riepilogo_finale.sh                  tutte le prove
#   bash riepilogo_finale.sh TestFinaleOnesto una sola prova
#
set -u

DIR=${DIR:-risultati_energia}
REGOLE="energia posizione disponibilita falso_aiuto banda impronta hop"
ETICHETTE="r1_energia r2_posizione r3_disponib r4_aiuto r5_banda r0_impronta r6_hop"

CONFIGS="${*:-TestFinaleOnesto TestFinaleAttacchi}"

# Nei registri delle regole il nodo osservato e' sempre il terzo campo.
conta() {
    grep -h "$2" $1 2>/dev/null | grep -v '^#' | awk '{print $3}' | sort | uniq -c \
        | awk '{print $2" "$1}'
}

for C in $CONFIGS; do
    if [ ! -d "$DIR/$C" ]; then
        echo "== $C: cartella $DIR/$C non trovata, salto"
        continue
    fi
    echo "================================================================"
    echo "  $C"
    echo "================================================================"

    for ESITO in VIOLATO DUBBIO; do
        TMP=$(mktemp)
        for R in $REGOLE; do
            conta "$DIR/$C/ant2_${R}_*.log" "$ESITO" | while read -r NODO N; do
                echo "$NODO $R $N"
            done
        done > "$TMP"

        if [ ! -s "$TMP" ]; then
            if [ "$ESITO" = "VIOLATO" ]; then
                echo
                echo "  NESSUNA VIOLAZIONE CERTA su nessun nodo."
            fi
            rm -f "$TMP"
            continue
        fi

        echo
        echo "  --- $ESITO, per nodo e per regola ---"
        # I nodi si ordinano qui con sort: asorti esiste solo in gawk.
        NODI=$(awk '{print $1}' "$TMP" | sort -u \
            | awk '{n = $0; gsub(/[^0-9]/, "", n); if (n == "") n = 0;
                    if ($0 ~ /^adh\[/) printf "1 %05d %s\n", n, $0;
                    else printf "2 %05d %s\n", n, $0}' \
            | sort -k1,1 -k2,2n -k3,3 | awk '{print $3}')

        awk -v etichette="$ETICHETTE" -v regole="$REGOLE" -v nodi="$NODI" '
        BEGIN {
            n = split(regole, R, " "); split(etichette, E, " ");
            for (i = 1; i <= n; i++) idx[R[i]] = i;
            m = split(nodi, ORD, "\n");
        }
        { v[$1 "," idx[$2]] += $3; }
        END {
            printf "  %-14s", "nodo";
            for (i = 1; i <= n; i++) printf "%13s", E[i];
            printf "%10s\n", "TOTALE";
            for (j = 1; j <= m; j++) {
                k = ORD[j];
                if (k == "") continue;
                tot = 0;
                printf "  %-14s", k;
                for (i = 1; i <= n; i++) {
                    val = v[k "," i] + 0;
                    tot += val;
                    printf "%13s", (val ? val : "-");
                }
                printf "%10d\n", tot;
            }
        }' "$TMP"
        rm -f "$TMP"
    done

    echo
    echo "  --- reclutamenti: chi ha chiesto aiuto e chi ha vinto ---"
    # Il diario dello scenario riporta i nomi dei droni, non gli indirizzi.
    grep -h AIUTO "$DIR/$C"/ant2_scenario_*.log 2>/dev/null | grep -v '^#' | grep 'scelto' \
        | awk '{tempo = $1; chi = $2; sub(/.*\| scelto /, "");
                printf "  t=%-9s %-9s chiede aiuto, vince %s\n", tempo, chi, $0}' \
        | sort -k1,1
    echo
done
