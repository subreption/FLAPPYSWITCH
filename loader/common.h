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

#ifndef _COMMON_H
#define _COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAX_PATH 1024

pid_t get_parent_pid(pid_t pid);
pid_t getpid_by_path(const char *target_path);
pid_t getppid_by_path(const char *target_path);

int halt_process(pid_t pid);
int resume_process(pid_t pid);

char *get_file_path_from_FILE(FILE *fp);
pid_t getpid_by_FILE(FILE *fp);
pid_t getppid_by_FILE(FILE *fp);

FILE *reopen_file_with_kill(FILE *f, pid_t *parent_pid_out);

int abspath_from_orig(const char *orig_path, const char *suffix, char *out, size_t outlen);
int check_and_fix_symlink(const char *src, const char *dst);

int acquire_global_lock(const char *name);

unsigned long find_library_base(const char *library_name);
void* get_symbol_address(const char *symbol_name);

static inline off_t get_file_size(const char *path) {
    struct stat st;

    if (lstat(path, &st) == 0) {
        return st.st_size;
    }

    return -1;
}

#endif

