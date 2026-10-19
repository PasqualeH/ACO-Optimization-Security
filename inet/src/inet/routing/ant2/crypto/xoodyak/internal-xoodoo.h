/*
 * ---------------------------------------------------------------------------
 * File vendorizzato (copiato nel progetto) per il livello di sicurezza Ant2.
 *   Fonte    : https://github.com/rweather/lwc-finalists  (Rhys Weatherley,
 *              stesso autore della Arduino Cryptography Library gia' usata
 *              in crypto/aead/)
 *   Versione : commit 77b23e672543df736bdcc8577590e8957fe0c58c (28/06/2022)
 *   Percorso : src/combined/internal-xoodoo.h
 *   Licenza  : MIT (testo completo in crypto/lwc-common/LICENSE.txt e qui sotto)
 *   Algoritmo: versione del ROUND FINALE NIST LWC (TinyJAMBU "v2", Xoodyak
 *              "round 3"), verificata con i KAT ufficiali dei pacchetti di
 *              sottomissione (vedi tools/test_kat_lwc.cc).
 * Modifiche rispetto all'originale (solo meccaniche, nessuna alla logica):
 *   - #include "internal-util.h" sostituito con "../lwc-common/internal-util.h"
 *     (il file e' condiviso dai due algoritmi).
 * ---------------------------------------------------------------------------
 */
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

#ifndef LW_INTERNAL_XOODOO_H
#define LW_INTERNAL_XOODOO_H

#include "../lwc-common/internal-util.h"

/**
 * \file internal-xoodoo.h
 * \brief Internal implementation of the Xoodoo permutation.
 *
 * References: https://keccak.team/xoodyak.html
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Number of rows in the Xoodoo state.
 */
#define XOODOO_ROWS 3

/**
 * \brief Number of columns in the Xoodoo state.
 */
#define XOODOO_COLS 4

/**
 * \brief Number of rounds for the Xoodoo permutation.
 */
#define XOODOO_ROUNDS 12

/**
 * \brief State information for the Xoodoo permutation.
 */
typedef union
{
    /** Words of the state organized into rows and columns */
    uint32_t S[XOODOO_ROWS][XOODOO_COLS];

    /** Words of the state as a single linear array */
    uint32_t W[XOODOO_ROWS * XOODOO_COLS];

    /** Bytes of the state */
    uint8_t B[XOODOO_ROWS * XOODOO_COLS * sizeof(uint32_t)];

} xoodoo_state_t;

/**
 * \brief Permutes the Xoodoo state.
 *
 * \param state The Xoodoo state.
 *
 * The state will be in little-endian before and after the operation.
 */
void xoodoo_permute(xoodoo_state_t *state);

#ifdef __cplusplus
}
#endif

#endif
