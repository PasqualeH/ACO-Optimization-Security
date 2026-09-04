#!/usr/bin/env python3
"""
analizza_risultati.py

Estrae le metriche di prestazione dai file .sca prodotti da OMNeT++ e produce
la tabella comparativa fra la configurazione CON sicurezza e quella SENZA.

Metriche estratte (le stesse usate nel paper di riferimento, sezione 5):
  - MOS          qualita' percepita della chiamata VoIP (1 = pessima, 5 = ottima)
  - Delay        ritardo end-to-end dei pacchetti VoIP
  - Packet loss  percentuale di pacchetti VoIP persi
  - Throughput   ricavato da packetReceived:sum(packetBytes) / durata

Uso:
    python3 analizza_risultati.py <cartella_results> [--csv risultati.csv]

Esempio:
    python3 analizza_risultati.py results/
"""

import sys
import os
import re
import math
import glob
from collections import defaultdict


def parse_sca(path):
    """
    Legge un file .sca di OMNeT++ e restituisce:
      attrs   -> attributi della run (configname, numero di run, parametri iterati)
      scalars -> dizionario (modulo, nome) -> valore
    Gestisce sia le righe 'scalar' sia i blocchi 'statistic' + 'field'.
    """
    attrs = {}
    scalars = {}
    stat_corrente = None

    with open(path, 'r', errors='replace') as f:
        for riga in f:
            riga = riga.rstrip('\n')
            if not riga or riga.startswith('#'):
                continue
            parti = riga.split()
            if not parti:
                continue
            tipo = parti[0]

            if tipo == 'attr' and len(parti) >= 3:
                attrs[parti[1]] = ' '.join(parti[2:]).strip('"')
                stat_corrente = None

            elif tipo == 'config' and len(parti) >= 3:
                # la durata puo' comparire come 'config sim-time-limit 60s'
                if parti[1] in ('sim-time-limit', 'simtimeLimit'):
                    attrs.setdefault(parti[1], ' '.join(parti[2:]).strip('"'))
                stat_corrente = None

            elif tipo == 'itervar' and len(parti) >= 3:
                attrs['itervar_' + parti[1]] = ' '.join(parti[2:]).strip('"')
                stat_corrente = None

            elif tipo == 'scalar' and len(parti) >= 4:
                modulo, nome, valore = parti[1], parti[2].strip('"'), parti[3]
                try:
                    scalars[(modulo, nome)] = float(valore)
                except ValueError:
                    pass
                stat_corrente = None

            elif tipo == 'statistic' and len(parti) >= 3:
                # apre un blocco: le righe 'field' successive appartengono a questo.
                # OMNeT++ nomina la statistica con il suffisso della modalita' di
                # registrazione (es. "mos:stats"): lo si rimuove per avere un nome
                # stabile indipendente da come e' stata configurata la raccolta.
                nome_stat = parti[2].strip('"')
                for suffisso in (':stats', ':histogram', ':vector'):
                    if nome_stat.endswith(suffisso):
                        nome_stat = nome_stat[:-len(suffisso)]
                        break
                stat_corrente = (parti[1], nome_stat)

            elif tipo == 'field' and len(parti) >= 3 and stat_corrente:
                modulo, nome = stat_corrente
                try:
                    scalars[(modulo, nome + ':' + parti[1])] = float(parti[2])
                except ValueError:
                    pass

    return attrs, scalars


def finiti(valori):
    """Scarta None e valori non finiti.

    OMNeT++ scrive 'mean nan' per le statistiche il cui campo 'count' e' 0,
    cioe' per i ricevitori che non hanno completato alcun talkspurt entro la
    fine della simulazione. Includerli propagherebbe NaN a tutta la media.
    """
    return [v for v in valori if v is not None and math.isfinite(v)]


def media(valori):
    v = finiti(valori)
    return sum(v) / len(v) if v else None


def deviazione(valori):
    v = finiti(valori)
    if len(v) < 2:
        return 0.0
    m = sum(v) / len(v)
    return (sum((x - m) ** 2 for x in v) / (len(v) - 1)) ** 0.5


def estrai_metriche(scalars, attrs):
    """Aggrega le statistiche dei singoli moduli nelle quattro metriche globali."""
    mos, delay, loss, byte_ricevuti = [], [], [], []

    for (modulo, nome), valore in scalars.items():
        # --- metriche VoIP (SimpleVoipReceiver, tipicamente su server1) ---
        if nome == 'mos:mean':
            mos.append(valore)
        elif nome == 'endToEndDelay:mean':
            delay.append(valore)
        elif nome == 'packetLossRate:mean':
            loss.append(valore)
        # --- traffico dati (UdpBasicApp, tipicamente su server2) ---
        elif nome == 'packetReceived:sum(packetBytes)':
            byte_ricevuti.append(valore)

    # durata della simulazione, per convertire i byte in bit/s
    durata = None
    for chiave in ('sim-time-limit', 'simtimeLimit'):
        if chiave in attrs:
            testo = re.sub(r'[^0-9.]', '', attrs[chiave])
            if testo:
                durata = float(testo)
            break

    throughput = None
    if byte_ricevuti and durata and durata > 0:
        throughput = sum(byte_ricevuti) * 8.0 / durata   # bit/s aggregati

    return {
        'mos': media(mos),
        'delay': media(delay),
        'loss': media(loss),
        'throughput': throughput,
        'voip_totali': len(mos),
        'voip_validi': len(finiti(mos)),
    }


def etichetta_scenario(attrs):
    """Identifica la configurazione e il valore del parametro iterato."""
    config = attrs.get('configname', '?')
    iterati = {k[len('itervar_'):]: v for k, v in attrs.items()
               if k.startswith('itervar_') and k != 'itervar_repetition'}
    if iterati:
        parte = ','.join(f'{k}={v}' for k, v in sorted(iterati.items()))
        return config, parte
    return config, '-'


def fmt(valore, cifre=3, scala=1.0):
    return f'{valore * scala:.{cifre}f}' if valore is not None else '   n/d'


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cartella = sys.argv[1]
    file_sca = sorted(glob.glob(os.path.join(cartella, '**', '*.sca'), recursive=True))
    if not file_sca:
        print(f"Nessun file .sca trovato in '{cartella}'.")
        print("Verifica che la configurazione abbia **.scalar-recording = true.")
        sys.exit(1)

    print(f"Trovati {len(file_sca)} file .sca in '{cartella}'\n")

    # raggruppa le ripetizioni per (configurazione, valore del parametro iterato)
    gruppi = defaultdict(list)
    for percorso in file_sca:
        attrs, scalars = parse_sca(percorso)
        metriche = estrai_metriche(scalars, attrs)
        gruppi[etichetta_scenario(attrs)].append(metriche)

    intestazione = (f"{'Configurazione':<26}{'Scenario':<16}{'run':>4}"
                    f"{'MOS':>9}{'±':>8}{'Delay(ms)':>12}{'Loss(%)':>10}{'Thr(Mbps)':>12}"
                    f"{'VoIP validi':>13}")
    print(intestazione)
    print('-' * len(intestazione))

    righe_csv = [('configurazione', 'scenario', 'ripetizioni', 'mos_media', 'mos_dev',
                  'delay_ms', 'loss_pct', 'throughput_mbps')]

    for (config, scenario) in sorted(gruppi.keys()):
        campioni = gruppi[(config, scenario)]
        mos_v = [c['mos'] for c in campioni]
        m_mos = media(mos_v)
        d_mos = deviazione(mos_v)
        m_delay = media([c['delay'] for c in campioni])
        m_loss = media([c['loss'] for c in campioni])
        m_thr = media([c['throughput'] for c in campioni])

        validi = sum(c['voip_validi'] for c in campioni)
        totali = sum(c['voip_totali'] for c in campioni)
        print(f"{config:<26}{scenario:<16}{len(campioni):>4}"
              f"{fmt(m_mos, 3):>9}{fmt(d_mos, 3):>8}"
              f"{fmt(m_delay, 2, 1000):>12}"
              f"{fmt(m_loss, 2, 100):>10}"
              f"{fmt(m_thr, 3, 1e-6):>12}"
              f"{str(validi) + '/' + str(totali):>13}")

        righe_csv.append((config, scenario, len(campioni),
                          fmt(m_mos, 4), fmt(d_mos, 4),
                          fmt(m_delay, 5), fmt(m_loss, 5), fmt(m_thr, 1)))

    print('-' * len(intestazione))
    print("\nMOS: 1=pessimo, 5=ottimo. Il paper indica come critici i ritardi")
    print("oltre 150 ms e come inaccettabili quelli oltre 300 ms.")
    print("\n'VoIP validi' = ricevitori che hanno completato almeno un talkspurt")
    print("sul totale dei ricevitori. Se molti sono a zero, la simulazione finisce")
    print("prima che le chiamate producano statistiche: allungare sim-time-limit.")

    if '--csv' in sys.argv:
        dest = sys.argv[sys.argv.index('--csv') + 1]
        with open(dest, 'w') as f:
            for riga in righe_csv:
                f.write(';'.join(str(c).strip() for c in riga) + '\n')
        print(f"\nTabella salvata in '{dest}' (separatore ';', importabile in Excel).")


if __name__ == '__main__':
    main()
