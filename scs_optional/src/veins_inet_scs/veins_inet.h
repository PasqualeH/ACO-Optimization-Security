//
// Copyright (C) 2019 Christoph Sommer <sommer@ccs-labs.org>
// Copyright (C) 2023 TOYOTA MOTOR CORPORATION. ALL RIGHTS RESERVED.
//
// Documentation for these modules is at http://veins.car2x.org/
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
// This program was developed based on Veins Framework (https://veins.car2x.org/). 
// The original code can be found at `veins_inet/src/veins_inet.h` of Veins-5.2.

#pragma once


#include "inet/common/INETDefs.h"
#include "veins/veins.h"

// Version number of last release ("major.minor.patch") or an alpha version, if nonzero
#define veins_inet_VERSION_MAJOR 5
#define veins_inet_VERSION_MINOR 2
#define veins_inet_VERSION_PATCH 0
#define veins_inet_VERSION_ALPHA 0

// Explicitly check Veins version number
#if !(VEINS_VERSION_MAJOR == 5 && VEINS_VERSION_MINOR >= 1)
#error Veins version 5.1 or compatible required
#endif

// Explicitly check INET version number
#if !(INET_VERSION >= 0x0402 && INET_VERSION < 0x0500)
#error INET version 4.2 or compatible required
#endif
//#if !((INET_VERSION == 0x0402) || (INET_VERSION == 0x0403))
#if !((INET_VERSION == 0x0402) || (INET_VERSION == 0x0403) || (INET_VERSION == 0x0404))
#pragma message("WARNING: Unsupported INET version. Only INET version 4,4, 4.2 and 4.3 are supported.")
#endif

// veins_sim5g_API macro. Allows us to use the same .h files for both building a .dll and linking against it
#if defined(veins_sim5g_EXPORT)
#define veins_sim5g_API OPP_DLLEXPORT
#elif defined(veins_sim5g_IMPORT)
#define veins_sim5g_API OPP_DLLIMPORT
#else
#define veins_sim5g_API
#endif
