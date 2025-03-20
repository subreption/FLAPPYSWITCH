/*
 * Copyright (C) 2025 ff794e44ea1c2b5211a3b07c57b5a3813f87f53ac10d78e56b16b79db6ff9615
 *                    b726ae7cf45cc4dfa8de359caffb893209bca614d9387a7666b106052fba3e50
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * DMCA Security Research Exemption:
 * Good faith security research performed consistent with 17 U.S.C. §1201(j) and
 * 37 CFR §201.40(b)(7) is explicitly permitted.
 *
 * This software is intended solely for educational, forensic, and lawful
 * security research purposes. Any use of this software for offensive or harmful
 * purposes is strictly prohibited.
 *
 * GENERAL DISCLAIMER:
 * This program is distributed WITHOUT ANY WARRANTY or guarantee of suitability.
 * The author explicitly disclaims responsibility and liability for any direct,
 * indirect, incidental, or consequential damages resulting from use or misuse.
 * Users accept all risks associated with use or distribution.
 *
 * Use, modification, or distribution constitutes explicit agreement to all terms
 * above.
 */

#ifndef _LOADER_H
#define _LOADER_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>
#include <arpa/inet.h>

#define MAX_PATH_LEN                1024
#define UNUSED_PARTITION_OFFSET     32768

#define PIVOT_TYPE_NONE             0
#define PIVOT_TYPE_ENTRYPOINT       1
#define PIVOT_TYPE_STAGE            2
#define PIVOT_TYPE_INFECT           3

#define SPECK256_KEY_SIZE           32

#define FUNK_MAGIC                  "FUNK"
#define PACKCFG_MAGIC               0xf986a2b1
#define PACKCFG_MARKER_OFFSET       10
#define PACKCFG_TFTP_ADDRS          4

typedef struct loader_pivot {
    uint32_t        seed;
    uint32_t        hash;
    const char      *original;
    int             type;
    int             fi_major_version;
    void            *extra;
    void            *extra2;
} loader_pivot_t;

struct loader_packed_config {
    uint32_t        magic;
    unsigned char   version;
    uint32_t        flags;
    struct in_addr  tftp_addrs[PACKCFG_TFTP_ADDRS];
} __attribute__((packed, aligned(1)));

typedef struct loader_infection_config {
    const char *path;
} loader_infection_config_t;

typedef struct loader_lib_entrypoint {
    const char *path;
} loader_lib_entrypoint_t;

typedef struct funk_carrier
{
} funk_carrier_t;

typedef struct funk_file
{
} funk_file_t;

typedef struct loader_state {
    Dl_info             dl_info;
    const char          *loaded_from;
    char                backup_path[MAX_PATH_LEN];
    int                 unused_partition_idx;
    size_t              backup_offset;

    int                 finished;

    struct loader_packed_config *packedcfg;
} loader_state_t;

int read_hidden_stream(const char *device_path);

#endif // _LOADER_H
