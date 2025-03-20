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

#ifndef _INFECTOR_H
#define _INFECTOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <elf.h>

#define INFECT_ERR_NO_DTDEBUG       -2
#define INFECT_ERR_NOTFOUND         -3
#define INFECT_ERR_WRITE            -4
#define INFECT_ERR_OPEN             -5

/* Program header type for dynamic segment */
#define PT_LOAD    1
#define PT_DYNAMIC 2

/* Dynamic tags */
#define DT_NULL    0
#define DT_NEEDED  1
#define DT_STRTAB  5
#define DT_STRSZ   10
#define DT_DEBUG   21

#define MAX_DT_NEEDED 32

typedef struct dt_needed_item {
    char name[64];
    unsigned int offset;
} dt_needed_item_t;

struct elf_dtn_infector_state {
    char path[1024];
    FILE *f;
    Elf32_Ehdr ehdr;
    Elf32_Dyn dyn;

    unsigned int dt_needed_offsets[MAX_DT_NEEDED];
    dt_needed_item_t dt_needed[MAX_DT_NEEDED];
    unsigned int dt_needed_count;
    unsigned int dt_needed_max_str_offset;

    int host_little;
    int file_little;

    unsigned int strtab_offset;

    unsigned int dynamic_offset;
    unsigned int dynamic_size;

    unsigned int phoff;
    unsigned int phnum;

    int debug_index;
    int strtab_index;

    unsigned int strtab_vaddr;
    unsigned int strtab_size;
};

typedef struct elf_dtn_infector_state elf_dtn_infector_state_t;

/* Swap functions */
static inline unsigned short swap16(unsigned short val) {
    return (val >> 8) | (val << 8);
}

static inline unsigned int swap32(unsigned int val) {
    return ((val & 0xFF000000) >> 24) |
           ((val & 0x00FF0000) >> 8)  |
           ((val & 0x0000FF00) << 8)  |
           ((val & 0x000000FF) << 24);
}

/* Detect host endianness */
static inline int is_host_little_endian(void) {
    unsigned int num = 1;
    return (*(char *)&num == 1);
}

int elf_dtn_infector_init(elf_dtn_infector_state_t *ei, const char *path);
int elf_dtn_infector_forge_dtneeded(elf_dtn_infector_state_t *ei,
    const char *target,
    int mode,
    unsigned int skip,
    char *forged_name,
    size_t namelen);

#endif
