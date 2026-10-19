#!/usr/bin/env python3
"""
analizza_aead.py

Confronto fra le configurazioni di sicurezza di Ant2 (algoritmi AEAD diversi,
piu' la baseline senza sicurezza). Estende analizza_risultati.py con tre cose
che servono per la Fase E:

  1. INTERVALLI DI CONFIDENZA al 95% invece della sola deviazione standard.
     Con 10 ripetizioni la deviazione da sola non dice se due configurazioni
     sono distinguibili; l'intervallo si'.
  2. Lettura dei file ant2_security_totals_*.txt, da cui arrivano i conteggi
     crittografici e il traffico di controllo (che la simulazione misura in
     modo deterministico).
  3. Stima del COSTO DI CPU, combinando i conteggi della simulazione con i
     tempi misurati dal microbenchmark. La simulazione da sola non puo'
     darla, perche' per OMNeT++ le operazioni crittografiche sono istantanee.

Uso:
    python3 analizza_aead.py <cartella_risultati> [<altra_cartella> ...] [opzioni]

Si possono passare PIU' cartelle: i risultati vengono messi nella stessa
tabella. Serve per confrontare le run gia' fatte (risultati_aead/) con quelle
dei due finalisti NIST LWC (risultati_aead_lwc/) senza spostare file.

Opzioni:
    --microbench FILE   output salvato di ./microbench, per la stima di CPU
    --csv FILE          salva la tabella in CSV (separatore ';')

Esempi:
    python3 analizza_aead.py risultati_aead/
    python3 analizza_aead.py risultati_aead/ --microbench microbench.txt --csv fase_e.csv
    python3 analizza_aead.py risultati_aead/ risultati_aead_lwc/ --microbench microbench.txt

Algoritmi riconosciuti: ascon128, aes128gcm, aes192gcm, aes256gcm,
chacha20poly1305, xoodyak, tinyjambu128 (piu' la baseline 'nosec').
ATTENZIONE: TinyJAMBU-128 ha un tag da 8 byte invece di 16, quindi i suoi
BANT e REQ sono 8 byte piu' corti (145 e 113 B invece di 153 e 121 B). Il
controllo di coerenza sulle dimensioni tiene conto di questa differenza.
"""

import sys
import os
import re
import math
import glob
from collections import defaultdict

# =============================================================================
# Lettura dei file .sca di OMNeT++
# =============================================================================

def pulisci(v):
    r"""
    Toglie virgolette ed escape dai valori letti dai .sca.

    Se nel .ini i valori sono stringhe quotate, come in
        **.routing.aeadAlgorithm = ${aead="ascon128","aes128gcm",...}
    OMNeT++ scrive nel .sca la riga   itervar aead ""ascon128""   e una
    semplice strip('"') lascia residui del tipo   "ascon128\   .
    """
    return v.strip().strip('"').replace('\\', '').strip('"').strip()


def parse_sca(path):
    """Restituisce (attrs, scalars) come in analizza_risultati.py."""
    attrs, scalars = {}, {}
    stat_corrente = None
    with open(path, 'r', errors='replace') as f:
        for riga in f:
            parti = riga.rstrip('\n').split()
            if not parti or parti[0].startswith('#'):
                continue
            tipo = parti[0]
            if tipo == 'attr' and len(parti) >= 3:
                attrs[parti[1]] = pulisci(' '.join(parti[2:]))
                stat_corrente = None
            elif tipo == 'config' and len(parti) >= 3:
                chiave = parti[1]
                valore = pulisci(' '.join(parti[2:]))
                if chiave in ('sim-time-limit', 'simtimeLimit'):
                    attrs.setdefault(chiave, valore)
                # Gli algoritmi non sempre sono variabili di iterazione: se uno
                # dei due e' fissato a un valore singolo compare solo qui.
                elif chiave.endswith('aeadAlgorithm'):
                    attrs.setdefault('cfg_aead', valore)
                elif chiave.endswith('signatureAlgorithm'):
                    attrs.setdefault('cfg_firma', valore)
                elif chiave.endswith('securityEnabled'):
                    attrs.setdefault('cfg_sec', valore)
                stat_corrente = None
            elif tipo == 'itervar' and len(parti) >= 3:
                attrs['itervar_' + parti[1]] = pulisci(' '.join(parti[2:]))
                stat_corrente = None
            elif tipo == 'scalar' and len(parti) >= 4:
                try:
                    scalars[(parti[1], parti[2].strip('"'))] = float(parti[3])
                except ValueError:
                    pass
                stat_corrente = None
            elif tipo == 'statistic' and len(parti) >= 3:
                # OMNeT++ aggiunge il suffisso della modalita' di registrazione
                # ("mos:stats"): lo si toglie per avere un nome stabile.
                nome = parti[2].strip('"')
                for suff in (':stats', ':histogram', ':vector'):
                    if nome.endswith(suff):
                        nome = nome[:-len(suff)]
                        break
                stat_corrente = (parti[1], nome)
            elif tipo == 'field' and len(parti) >= 3 and stat_corrente:
                mod, nome = stat_corrente
                try:
                    scalars[(mod, nome + ':' + parti[1])] = float(parti[2])
                except ValueError:
                    pass
    return attrs, scalars


def estrai_metriche(scalars, attrs):
    mos, delay, loss, byte_ric = [], [], [], []
    for (_, nome), valore in scalars.items():
        if nome == 'mos:mean':
            mos.append(valore)
        elif nome == 'endToEndDelay:mean':
            delay.append(valore)
        elif nome == 'packetLossRate:mean':
            loss.append(valore)
        elif nome == 'packetReceived:sum(packetBytes)':
            byte_ric.append(valore)

    durata = None
    for chiave in ('sim-time-limit', 'simtimeLimit'):
        if chiave in attrs:
            testo = re.sub(r'[^0-9.]', '', attrs[chiave])
            if testo:
                durata = float(testo)
            break

    thr = sum(byte_ric) * 8.0 / durata if (byte_ric and durata) else None
    return {'mos': media(mos), 'delay': media(delay), 'loss': media(loss),
            'throughput': thr,
            'voip_validi': len(finiti(mos)), 'voip_totali': len(mos)}


def valore_algoritmo(attrs, nome_itervar, chiave_cfg):
    """
    Recupera un algoritmo dalla run, provando in ordine:
      1. la variabile di iterazione (se l'algoritmo era sotto sweep)
      2. la voce di configurazione (se era fissato a un valore singolo)
    Restituisce None se non e' determinabile.
    """
    v = attrs.get('itervar_' + nome_itervar)
    if v:
        return v
    v = attrs.get(chiave_cfg)
    # se e' ancora nella forma ${...} non e' un valore utilizzabile
    if v and not v.startswith('$'):
        return v
    return None


def etichetta_config(attrs, aead_forzato=None):
    """
    Etichetta della configurazione di sicurezza.

    Deve coincidere con quella che Ant2.cc usa nei nomi dei file
    ant2_security_totals_*, altrimenti le tabelle A e B non si possono
    accostare. In quel codice l'algoritmo di firma compare SOLO se non e'
    quello predefinito, quindi qui si omette '_ed25519'.

      campagna AEAD  -> 'ascon128', 'aes256gcm', ...
      campagna firme -> 'ascon128' (braccio Ed25519)
                        'ascon128_ecdsap256' (braccio ECDSA)
      baseline       -> 'nosec'
    """
    if attrs.get('cfg_sec', '').lower() == 'false':
        return 'nosec'

    aead = valore_algoritmo(attrs, 'aead', 'cfg_aead') or aead_forzato
    firma = valore_algoritmo(attrs, 'firma', 'cfg_firma') or 'ed25519'

    if aead:
        return aead if firma == 'ed25519' else aead + '_' + firma

    nome = attrs.get('configname', '?')
    if 'baseline' in nome.lower() or 'senzasicurezza' in nome.lower():
        return 'nosec'
    return nome


def scomponi(tag):
    """Da 'ascon128_ecdsap256' ricava ('ascon128', 'ecdsap256')."""
    for firma in ('ecdsap256', 'ed25519'):
        if tag.endswith('_' + firma):
            return tag[:-(len(firma) + 1)], firma
    return tag, 'ed25519'


def etichetta_carico(attrs):
    return attrs.get('itervar_numUEs', attrs.get('itervar_numUe', '-'))


# =============================================================================
# Statistica
# =============================================================================

# Valori critici della t di Student, bilaterale, livello 95%, per gradi di
# liberta' da 1 a 30. Oltre i 30 si usa 1.96 (approssimazione normale).
T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
       8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160,
       14: 2.145, 15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093,
       20: 2.086, 21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
       26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042}


def finiti(valori):
    """Scarta None e NaN. OMNeT++ scrive 'mean nan' quando count vale 0."""
    return [v for v in valori if v is not None and math.isfinite(v)]


def media(valori):
    v = finiti(valori)
    return sum(v) / len(v) if v else None


def dev_std(valori):
    v = finiti(valori)
    if len(v) < 2:
        return 0.0
    m = sum(v) / len(v)
    return (sum((x - m) ** 2 for x in v) / (len(v) - 1)) ** 0.5


def mediana(valori):
    v = sorted(finiti(valori))
    if not v:
        return None
    n = len(v)
    return v[n // 2] if n % 2 else (v[n // 2 - 1] + v[n // 2]) / 2.0


def semiampiezza_ic95(valori):
    """Semiampiezza dell'intervallo di confidenza al 95% sulla media."""
    v = finiti(valori)
    n = len(v)
    if n < 2:
        return None
    t = T95.get(n - 1, 1.96)
    return t * dev_std(v) / math.sqrt(n)


def intervalli_si_sovrappongono(a, b):
    """a e b sono coppie (media, semiampiezza). None se non calcolabile."""
    if not a or not b or a[0] is None or b[0] is None or a[1] is None or b[1] is None:
        return None
    return not (a[0] + a[1] < b[0] - b[1] or b[0] + b[1] < a[0] - a[1])


# =============================================================================
# Lettura dei file ant2_security_totals_*.txt
# =============================================================================

def runnum_da_nome(path):
    """Estrae N da 'ant2_security_totals_<tag>_rN.txt'."""
    m = re.search(r'_r(\d+)\.txt$', os.path.basename(path))
    return int(m.group(1)) if m else None


def parse_totals(path):
    """Estrae conteggi crittografici e traffico di controllo da un file totals."""
    testo = open(path, 'r', errors='replace').read()

    def num(pattern, default=None):
        m = re.search(pattern, testo)
        return float(m.group(1)) if m else default

    # L'etichetta si prende dal NOME DEL FILE, che e' esattamente quella che
    # Ant2.cc ha usato (secTagFile): comprende sia l'AEAD sia, quando non e'
    # quello predefinito, l'algoritmo di firma. La riga 'config: aead=...'
    # dentro il file riporta solo l'AEAD, quindi non basta a distinguere i due
    # bracci di una campagna sulle firme.
    m = re.search(r'ant2_security_totals_(.+)_r\d+\.txt$', os.path.basename(path))
    tag = m.group(1) if m else None
    if tag is None:
        m = re.search(r'config:\s*aead=(\S+)', testo)
        tag = m.group(1) if m else 'sconosciuto'
        if tag == 'nessuno':
            tag = 'nosec'

    return {
        'tag': tag,
        'verificati': num(r'TOTALE verificati:\s*(\d+)'),
        'scartati': num(r'TOTALE verificati:\s*\d+\s+scartati:\s*(\d+)'),
        'sconosciuta': num(r'identita.*?:\s*(\d+)'),
        'firma_ko': num(r'firma Ed25519 non valida:\s*(\d+)'),
        'tag_ko': num(r'payload manomesso[^:]*:\s*(\d+)'),
        'ctrl_msg': num(r'TOTALE:\s*(\d+) messaggi'),
        'ctrl_byte': num(r'TOTALE:\s*\d+ messaggi,\s*(\d+) byte'),
        'dim_media': num(r'Dimensione media:\s*([0-9.]+)'),
        'bant_ok': num(r'BANT\s+verificati:\s*(\d+)'),
        'req_ok': num(r'REQ\s+verificati:\s*(\d+)'),
        'fant_ok': num(r'FANT\s+verificati:\s*(\d+)'),
        # traffico per tipo di messaggio: serve al controllo di coerenza sulle
        # dimensioni, che va fatto per TIPO e non sulla media complessiva
        'fant_msg': num(r'FANT\s*:\s*(\d+) messaggi'),
        'fant_byte': num(r'FANT\s*:\s*\d+ messaggi,\s*(\d+) byte'),
        'bant_msg': num(r'BANT\s*:\s*(\d+) messaggi'),
        'bant_byte': num(r'BANT\s*:\s*\d+ messaggi,\s*(\d+) byte'),
        'req_msg': num(r'REQ\s*:\s*(\d+) messaggi'),
        'req_byte': num(r'REQ\s*:\s*\d+ messaggi,\s*(\d+) byte'),
        'runnum': runnum_da_nome(path),
    }


# =============================================================================
# Lettura dell'output del microbenchmark
# =============================================================================

NOMI_MICROBENCH = {
    'Ascon-AEAD128': 'ascon128',
    'AES-128-GCM': 'aes128gcm',
    'AES-192-GCM': 'aes192gcm',
    'AES-256-GCM': 'aes256gcm',
    'ChaCha20-Poly1305': 'chacha20poly1305',
    'Xoodyak': 'xoodyak',
    'TinyJAMBU-128': 'tinyjambu128',
}

# Lunghezza del tag AEAD (byte). Tutti 16 tranne TinyJAMBU-128.
TAG_LEN = {'ascon128': 16, 'aes128gcm': 16, 'aes192gcm': 16, 'aes256gcm': 16,
           'chacha20poly1305': 16, 'xoodyak': 16, 'tinyjambu128': 8}


def dimensioni_attese(tag):
    """
    Dimensione attesa (byte) di FANT, BANT e REQ per una configurazione,
    con la stessa formula usata in Ant2.cc:
      FANT = 16 + firma(64)                         = 80 B  (non cifrato)
      BANT = 20 + payload(53) + tag + firma(64)      = 137 + tag
      REQ  = 16 + payload(25) + tag + firma(64)      = 105 + tag
    Baseline senza sicurezza: 16 B per tutti e tre.
    Restituisce None se l'AEAD non e' riconosciuto.
    """
    if tag == 'nosec':
        return {'fant': 16.0, 'bant': 16.0, 'req': 16.0}
    aead, _ = scomponi(tag)
    if aead not in TAG_LEN:
        return None
    t = TAG_LEN[aead]
    return {'fant': 80.0, 'bant': 137.0 + t, 'req': 105.0 + t}


def parse_microbench(path):
    """
    Legge l'output di ./microbench e restituisce:
      tempi[tag_aead] = {'dec_bant': us, 'dec_req': us}
      verifiche = {'ed25519': us, 'ecdsap256': us,
                   'ed25519_tag8': us, 'ecdsap256_tag8': us}
    Le voci '_tag8' sono la verifica del blocco firmato del BANT quando il
    tag e' di 8 byte (TinyJAMBU-128): 73 B invece di 81. Le scrive solo la
    versione aggiornata di microbench.cc; con un output vecchio mancano e si
    usa il valore a 81 B (differenza trascurabile, ma va detto).

    ATTENZIONE al punto delicato: l'output contiene DUE righe
    "verifica blocco BANT", una nella sezione Ed25519 e una in quella ECDSA.
    Bisogna quindi tenere conto di quale sezione si sta leggendo, altrimenti
    il secondo valore sovrascrive il primo e si attribuisce a Ed25519 il
    costo di ECDSA, che e' tre volte tanto.
    """
    tempi, verifiche = {}, {}
    sezione = 'ed25519'
    for riga in open(path, 'r', errors='replace'):
        if 'autenticazione' in riga:
            sezione = 'ecdsap256' if 'ECDSA' in riga else 'ed25519'

        for nome, tag in NOMI_MICROBENCH.items():
            if riga.startswith(nome):
                v = re.findall(r'([0-9.]+)\s*us', riga)
                if len(v) >= 4:
                    tempi[tag] = {'dec_bant': float(v[1]), 'dec_req': float(v[3])}
                break

        m = re.search(r'verifica\s+blocco BANT.*?:\s*([0-9.]+)\s*us', riga)
        if m:
            # Anche qui: la riga del blocco da 73 B (tag 8 B) NON deve
            # sovrascrivere quella da 81 B, che e' il caso di tutti gli altri AEAD.
            chiave = sezione + '_tag8' if '73 B' in riga else sezione
            verifiche[chiave] = float(m.group(1))
    return tempi, verifiche


# =============================================================================
# Stampa
# =============================================================================

def fmt(v, cifre=3, scala=1.0):
    return f'{v * scala:.{cifre}f}' if v is not None else 'n/d'


def fmt_ic(m, ic, cifre=3, scala=1.0):
    if m is None:
        return 'n/d'
    if ic is None:
        return f'{m * scala:.{cifre}f}'
    return f'{m * scala:.{cifre}f} ±{ic * scala:.{cifre}f}'


ORDINE = ['nosec', 'ascon128', 'ascon128_ecdsap256',
          'chacha20poly1305', 'aes128gcm', 'aes192gcm', 'aes256gcm',
          'xoodyak', 'tinyjambu128']


def chiave_ordine(tag):
    return (ORDINE.index(tag) if tag in ORDINE else 99, tag)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    # Tutti gli argomenti posizionali (cioe' quelli che non sono opzioni o
    # valori di opzioni) sono cartelle di risultati.
    opzioni_con_valore = ('--microbench', '--csv', '--aead')
    cartelle, salta = [], False
    for a in sys.argv[1:]:
        if salta:
            salta = False
            continue
        if a in opzioni_con_valore:
            salta = True
            continue
        cartelle.append(a)
    cartella = ', '.join(cartelle)
    file_microbench = None
    if '--microbench' in sys.argv:
        file_microbench = sys.argv[sys.argv.index('--microbench') + 1]
    # Da usare quando l'AEAD e' fissato nel .ini e non compare nei .sca:
    #   python3 analizza_aead.py risultati_firma/ --aead ascon128
    aead_forzato = None
    if '--aead' in sys.argv:
        aead_forzato = sys.argv[sys.argv.index('--aead') + 1]

    # ---- 1. metriche di rete dai .sca ------------------------------------
    file_sca = sorted(f for c in cartelle
                      for f in glob.glob(os.path.join(c, '**', '*.sca'), recursive=True))
    if not file_sca:
        print(f"Nessun file .sca trovato in '{cartella}'.")
        sys.exit(1)

    gruppi = defaultdict(list)
    # mappa (tag, numero di run) -> carico, per poter attribuire ogni file di
    # totali al carico giusto: il nome del file contiene solo l'algoritmo.
    mappa_run = {}
    for percorso in file_sca:
        attrs, scalars = parse_sca(percorso)
        tag = etichetta_config(attrs, aead_forzato)
        carico = etichetta_carico(attrs)
        gruppi[(tag, carico)].append(estrai_metriche(scalars, attrs))
        if 'runnumber' in attrs:
            try:
                mappa_run[(tag, int(attrs['runnumber']))] = carico
            except ValueError:
                pass

    # ---- 2. conteggi di sicurezza dai .txt --------------------------------
    file_tot = sorted(f for c in cartelle
                      for f in glob.glob(os.path.join(c, '**', 'ant2_security_totals_*.txt'),
                                         recursive=True))
    tot_per_tag = defaultdict(list)
    for percorso in file_tot:
        d = parse_totals(percorso)
        d['carico'] = mappa_run.get((d['tag'], d['runnum']), '-')
        tot_per_tag[(d['tag'], d['carico'])].append(d)

    print(f"File .sca letti: {len(file_sca)}   file totals letti: {len(file_tot)}\n")

    non_riconosciute = [t for t, _ in gruppi
                        if t != 'nosec' and '_' not in t and t not in ORDINE]
    if non_riconosciute:
        print("  AVVISO: non sono riuscito a dedurre l'algoritmo per queste run:")
        for t in sorted(set(non_riconosciute)):
            print(f"    {t}")
        print("  Rilancia indicando l'AEAD fisso, per esempio:")
        print("    python3 analizza_aead.py <cartella> --aead ascon128\n")

    # ---- Tabella A: metriche di rete --------------------------------------
    print("=" * 100)
    print(" A. METRICHE DI RETE  (media con intervallo di confidenza al 95%)")
    print("=" * 100)
    testa = (f"{'configurazione':<20}{'carico':>7}{'run':>5}"
             f"{'MOS':>17}{'Delay medio (ms)':>22}{'Delay med.':>12}"
             f"{'Loss (%)':>15}{'Thr (Mbps)':>12}{'VoIP ok':>10}")
    print(testa)
    print('-' * len(testa))

    riepilogo_mos = {}
    avvisi_coda = []
    righe_csv = [('tabella', 'configurazione', 'carico', 'ripetizioni',
                  'mos', 'mos_ic95', 'delay_ms', 'delay_ic95_ms',
                  'loss_pct', 'throughput_mbps')]

    for chiave in sorted(gruppi.keys(), key=lambda k: (chiave_ordine(k[0]), k[1])):
        campioni = gruppi[chiave]
        tag, carico = chiave
        serie = {n: [c[n] for c in campioni] for n in ('mos', 'delay', 'loss', 'throughput')}
        m = {n: media(serie[n]) for n in serie}
        ic = {n: semiampiezza_ic95(serie[n]) for n in serie}

        if carico != '-':
            riepilogo_mos.setdefault(carico, {})[tag] = (m['mos'], ic['mos'])

        med_delay = mediana(serie['delay'])
        validi = sum(c['voip_validi'] for c in campioni)
        totali = sum(c['voip_totali'] for c in campioni)
        print(f"{tag:<20}{carico:>7}{len(campioni):>5}"
              f"{fmt_ic(m['mos'], ic['mos'], 3):>17}"
              f"{fmt_ic(m['delay'], ic['delay'], 1, 1000):>22}"
              f"{fmt(med_delay, 1, 1000):>12}"
              f"{fmt_ic(m['loss'], ic['loss'], 2, 100):>15}"
              f"{fmt(m['throughput'], 3, 1e-6):>12}"
              f"{str(validi) + '/' + str(totali):>10}")

        # Segnala le medie inaffidabili: se l'intervallo e' largo quanto la
        # media, la distribuzione ha una coda pesante e la media non e' un
        # buon riassunto. Meglio guardare la mediana.
        if m['delay'] and ic['delay'] and ic['delay'] > 0.5 * m['delay']:
            avvisi_coda.append((tag, carico, m['delay'], ic['delay'], med_delay))

        righe_csv.append(('rete', tag, carico, len(campioni),
                          fmt(m['mos'], 4), fmt(ic['mos'], 4),
                          fmt(m['delay'], 5, 1000), fmt(ic['delay'], 5, 1000),
                          fmt(m['loss'], 5, 100), fmt(m['throughput'], 1, 1e-6)))

    # ---- Avvisi sulla stabilita' delle medie ------------------------------
    if avvisi_coda:
        print()
        print("  ATTENZIONE - medie del ritardo poco affidabili:")
        for tag, carico, m, ic, med in avvisi_coda:
            print(f"    {tag:<20} carico {carico:>3}: media {m*1000:.0f} ms "
                  f"(± {ic*1000:.0f}), mediana {med*1000:.0f} ms")
        print("    L'intervallo di confidenza e' largo quanto la media: la")
        print("    distribuzione ha una coda pesante e poche run estreme la")
        print("    dominano. Usare la mediana, o aumentare le ripetizioni.")

    # ---- Verdetto sulla distinguibilita' ----------------------------------
    print()
    for carico, per_tag in sorted(riepilogo_mos.items()):
        aead = {t: v for t, v in per_tag.items() if t != 'nosec'}
        if len(aead) < 2:
            continue
        tutti_sovrapposti = True
        for a in aead:
            for b in aead:
                if a < b and intervalli_si_sovrappongono(aead[a], aead[b]) is False:
                    tutti_sovrapposti = False
                    print(f"  carico {carico}: MOS di {a} e {b} NON si sovrappongono "
                          f"-> differenza da approfondire")
        if tutti_sovrapposti:
            print(f"  carico {carico}: gli intervalli di confidenza del MOS si sovrappongono")
            print(f"                per tutte le coppie di algoritmi AEAD.")
            print(f"                -> nessuna evidenza di un effetto dell'algoritmo sul MOS.")

    # ---- Tabella B: sicurezza e traffico di controllo ---------------------
    if tot_per_tag:
        print()
        print("=" * 100)
        print(" B. LIVELLO DI SICUREZZA E TRAFFICO DI CONTROLLO  (medie sulle run)")
        print("=" * 100)
        testa = (f"{'configurazione':<20}{'carico':>7}{'run':>5}{'verificati':>12}{'scartati':>10}"
                 f"{'msg ctrl':>11}{'byte ctrl':>13}{'B/msg':>8}")
        print(testa)
        print('-' * len(testa))

        base_byte = {}
        for chiave in sorted(tot_per_tag.keys(), key=lambda k: (chiave_ordine(k[0]), k[1])):
            tag, carico = chiave
            d = tot_per_tag[chiave]
            def med(k):
                return media([x[k] for x in d])
            if tag == 'nosec':
                base_byte[carico] = med('ctrl_byte')
            print(f"{tag:<20}{carico:>7}{len(d):>5}{fmt(med('verificati'), 0):>12}"
                  f"{fmt(med('scartati'), 0):>10}{fmt(med('ctrl_msg'), 0):>11}"
                  f"{fmt(med('ctrl_byte'), 0):>13}{fmt(med('dim_media'), 1):>8}")
            righe_csv.append(('sicurezza', tag, carico, len(d),
                              fmt(med('verificati'), 0), fmt(med('scartati'), 0),
                              fmt(med('ctrl_msg'), 0), fmt(med('ctrl_byte'), 0),
                              fmt(med('dim_media'), 2), ''))

        if base_byte:
            print()
            print("  Rapporto rispetto alla baseline senza sicurezza:")
            for chiave in sorted(tot_per_tag.keys(), key=lambda k: (chiave_ordine(k[0]), k[1])):
                tag, carico = chiave
                if tag == 'nosec' or carico not in base_byte:
                    continue
                b = media([x['ctrl_byte'] for x in tot_per_tag[chiave]])
                if b:
                    print(f"    {tag:<20} carico {carico:>3}: "
                          f"{b / base_byte[carico]:.2f}x in byte di controllo")

        # --- controllo di coerenza sulle dimensioni, PER TIPO di messaggio ---
        # La media complessiva NON e' un buon indicatore: dipende dalla
        # proporzione fra FANT, BANT e REQ, che cambia da run a run per effetto
        # della casualita'. La dimensione media di CIASCUN TIPO, invece, deve
        # coincidere con quella attesa per la lunghezza del tag dell'algoritmo:
        # identica per i sei AEAD con tag da 16 B, 8 B in meno su BANT e REQ
        # per TinyJAMBU-128 (tag da 8 B).
        print()
        print("  Controllo di coerenza: dimensione media per TIPO di messaggio (byte)")
        testa2 = (f"    {'configurazione':<20}{'FANT':>10}{'BANT':>10}{'REQ':>10}"
                  f"{'attesi F/B/R':>16}")
        print(testa2)
        print('    ' + '-' * (len(testa2) - 4))
        per_tipo = defaultdict(dict)
        for chiave in sorted(tot_per_tag.keys(), key=lambda k: (chiave_ordine(k[0]), k[1])):
            tag, carico = chiave
            d = tot_per_tag[chiave]
            riga = {}
            for tipo in ('fant', 'bant', 'req'):
                msg = sum(x[tipo + '_msg'] or 0 for x in d)
                byte = sum(x[tipo + '_byte'] or 0 for x in d)
                riga[tipo] = byte / msg if msg else None
            etichetta = f"{tag} ({carico})" if carico != '-' else tag
            attese = dimensioni_attese(tag)
            testo_attese = (f"{attese['fant']:.0f}/{attese['bant']:.0f}/{attese['req']:.0f}"
                            if attese else 'n/d')
            print(f"    {etichetta:<20}{fmt(riga['fant'], 2):>10}"
                  f"{fmt(riga['bant'], 2):>10}{fmt(riga['req'], 2):>10}{testo_attese:>16}")
            if attese:
                for tipo, v in riga.items():
                    # Un tipo di messaggio mai trasmesso (v None) non e' un errore.
                    if v is not None and abs(v - attese[tipo]) > 0.05:
                        per_tipo[tipo][etichetta] = (v, attese[tipo])

        print()
        if per_tipo:
            for tipo, valori in per_tipo.items():
                for etichetta, (v, att) in valori.items():
                    print(f"    ATTENZIONE: {tipo.upper()} di {etichetta} misura {v:.2f} B, "
                          f"attesi {att:.0f} B.")
            print("    Non dovrebbe accadere: verificare la configurazione.")
        else:
            print("    CONTROLLO SUPERATO: per ogni tipo di messaggio la dimensione coincide")
            print("    con quella attesa (FANT 80 B; BANT 153 B e REQ 121 B per i sei AEAD con")
            print("    tag da 16 B; BANT 145 B e REQ 113 B per TinyJAMBU-128, tag da 8 B).")
            print("    La media complessiva della tabella sopra varia solo perche' cambia")
            print("    la PROPORZIONE fra FANT, BANT e REQ da una run all'altra.")

    # ---- Tabella C: costo di CPU -----------------------------------------
    if file_microbench and tot_per_tag:
        tempi, verifiche = parse_microbench(file_microbench)
        if tempi and verifiche:
            # Carico di lavoro di riferimento, uguale per tutte le
            # configurazioni. PERCHE': il numero di messaggi verificati varia
            # di circa il 10% fra configurazioni, ma per effetto del seme
            # aleatorio, non dell'algoritmo. Moltiplicando i tempi per i
            # conteggi effettivi, quella variazione casuale sommergerebbe la
            # differenza reale fra algoritmi. Il confronto corretto usa lo
            # stesso carico per tutti e fa variare solo i tempi misurati.
            tutti_ver = [x['verificati'] for d in tot_per_tag.values() for x in d
                         if x['verificati']]
            tutti_dec = [(x['bant_ok'] or 0) + (x['req_ok'] or 0)
                         for d in tot_per_tag.values() for x in d
                         if (x['bant_ok'] or x['req_ok'])]
            rif_ver = media(tutti_ver) or 0
            rif_dec = media(tutti_dec) or 0

            print()
            print("=" * 100)
            print(" C. COSTO DI CPU")
            print(" (conteggi della simulazione x tempi misurati dal microbenchmark)")
            print("=" * 100)
            print(" Carico di lavoro di riferimento, uguale per tutte le configurazioni:")
            print(f"   {rif_ver:.0f} verifiche di firma + {rif_dec:.0f} decifrature per run")
            print()
            testa = (f"{'configurazione':<26}{'verifica firma':>16}{'decifra':>11}"
                     f"{'CPU a parita di traffico':>27}{'vs riferimento':>16}")
            print(testa)
            print('-' * len(testa))

            # una riga per ogni configurazione effettivamente presente
            etichette = sorted({k[0] for k in tot_per_tag if k[0] != 'nosec'},
                               key=chiave_ordine)
            righe, base_cpu = [], None
            for tag in etichette:
                aead, firma = scomponi(tag)
                if aead not in tempi or firma not in verifiche:
                    continue
                v = verifiche[firma]
                # Con tag da 8 B (TinyJAMBU-128) il blocco firmato e' piu' corto:
                # si usa il tempo misurato su quel blocco, se disponibile.
                if TAG_LEN.get(aead) == 8:
                    v = verifiche.get(firma + '_tag8', v)
                d = tempi[aead]['dec_bant']
                cpu_ms = (rif_ver * v + rif_dec * d) / 1000.0
                righe.append((tag, v, d, cpu_ms))
                if base_cpu is None:
                    base_cpu = cpu_ms       # la prima riga fa da riferimento

            for tag, v, d, cpu_ms in righe:
                rapporto = f"{cpu_ms / base_cpu:.4f}x" if base_cpu else '-'
                print(f"{tag:<26}{v:>13.1f} us{d:>8.3f} us"
                      f"{cpu_ms:>24.1f} ms{rapporto:>16}")
                righe_csv.append(('cpu', tag, '-', '', f'{v:.2f}', f'{d:.3f}',
                                  f'{cpu_ms:.2f}', rapporto, '', ''))

            if righe:
                print()
                print(f"  Riferimento (1.0000x): {righe[0][0]}")
                firme_usate = {scomponi(t)[1] for t, _, _, _ in righe}
                if len(firme_usate) > 1:
                    print("  La colonna che cambia di piu' e' la verifica della firma:")
                    for f_ in sorted(firme_usate):
                        print(f"    {f_:<12} {verifiche[f_]:>8.1f} us per verifica")
                else:
                    print("  La verifica della firma e' identica in tutte le configurazioni:")
                    print("  e' la voce dominante e non dipende dall'AEAD. La differenza fra")
                    print("  le righe viene solo dalla colonna 'decifra'.")
                    if any(TAG_LEN.get(scomponi(t)[0]) == 8 for t, _, _, _ in righe):
                        print("  Unica eccezione: con TinyJAMBU-128 (tag da 8 B) il blocco firmato")
                        print("  del BANT e' di 73 B invece di 81, quindi la verifica e' misurata")
                        print("  su un blocco leggermente piu' corto (effetto minimo).")

            print()
            print("  Conteggi effettivi osservati (NON usati per il confronto sopra):")
            for chiave in sorted(tot_per_tag.keys(), key=lambda k: (chiave_ordine(k[0]), k[1])):
                tag, carico = chiave
                v = media([x['verificati'] for x in tot_per_tag[chiave]])
                if v:
                    scarto = 100.0 * (v - rif_ver) / rif_ver if rif_ver else 0
                    print(f"    {tag:<26} carico {carico:>3}: {v:>9.0f} verifiche "
                          f"({scarto:+.1f}% rispetto al riferimento)")
        else:
            print(f"\nNon sono riuscito a leggere i tempi da '{file_microbench}'.")
            print("Verifica che sia l'output completo di ./microbench.")

    # ---- CSV --------------------------------------------------------------
    if '--csv' in sys.argv:
        dest = sys.argv[sys.argv.index('--csv') + 1]
        with open(dest, 'w') as f:
            for riga in righe_csv:
                f.write(';'.join(str(c).strip() for c in riga) + '\n')
        print(f"\nTabella salvata in '{dest}' (separatore ';', importabile in Excel).")


if __name__ == '__main__':
    main()
