/*
 * ---------------------------------------------------------------------------
 * File vendorizzato (copiato nel progetto) per il livello di sicurezza Ant2.
 *   Fonte    : https://github.com/rweather/lwc-finalists  (Rhys Weatherley,
 *              stesso autore della Arduino Cryptography Library gia' usata
 *              in crypto/aead/)
 *   Versione : commit 77b23e672543df736bdcc8577590e8957fe0c58c (28/06/2022)
 *   Percorso : src/combined/internal-util.c
 *   Licenza  : MIT (testo completo in crypto/lwc-common/LICENSE.txt e qui sotto)
 *   Algoritmo: versione del ROUND FINALE NIST LWC (TinyJAMBU "v2", Xoodyak
 *              "round 3"), verificata con i KAT ufficiali dei pacchetti di
 *              sottomissione (vedi tools/test_kat_lwc.cc).
 * Modifiche rispetto all'originale (solo meccaniche, nessuna alla logica):
 *   - estensione rinominata da .c a .cc, perche' opp_makemake compila solo
 *     .cc/.cpp (con .c il file verrebbe ignorato in silenzio);
 *   - contenuto racchiuso in extern "C" { ... } per mantenere i nomi C
 *     (nessun name-mangling), come gia' fatto per crypto/ascon;
 * ---------------------------------------------------------------------------
 */
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "internal-util.h"

int aead_check_tag
    (unsigned char *plaintext, size_t plaintext_len,
     const unsigned char *tag1, const unsigned char *tag2, size_t size)
{
    /* Set "accum" to -1 if the tags match, or 0 if they don't match */
    int accum = 0;
    while (size > 0) {
        accum |= (*tag1++ ^ *tag2++);
        --size;
    }
    accum = (accum - 1) >> 8;

    /* Destroy the plaintext if the tag match failed */
    while (plaintext_len > 0) {
        *plaintext++ &= accum;
        --plaintext_len;
    }

    /* If "accum" is 0, return -1, otherwise return 0 */
    return ~accum;
}

void aead_clean(void *buf, unsigned size)
{
    /* Force the use of volatile so that we actually clear the memory.
     * Otherwise the compiler might optimise the entire contents of this
     * function away, which will not be secure.
     *
     * Even this may not work.  Some platforms have bzero_explicit() or
     * memset_s() that could be used in place of this implementation. */
    volatile uint8_t *d = (volatile uint8_t *)buf;
    while (size > 0) {
        *d++ = 0;
        --size;
    }
}

#ifdef __cplusplus
} /* extern "C" */
#endif
