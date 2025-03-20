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
#include <fcntl.h>
#include <semaphore.h>
#include <limits.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <libgen.h>
#include <dlfcn.h>
#include "debug.h"
#include "common.h"

/*
 * find_library_base()
 *  - Parses /proc/self/maps to locate the load base address
 *    of a shared library that contains the given substring (library_name).
 *
 * Returns:
 *  - The base address (an unsigned long) on success,
 *  - 0 if not found or on error.
 */
unsigned long find_library_base(const char *library_name)
{
    FILE *fp;
    char line[512];
    unsigned long base_addr = 0;

    fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        debug_perror("fopen");
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start, end;
        char perm[5], dev[6], mapname[256];
        unsigned int offset, inode;

        int n = sscanf(line, "%lx-%lx %4s %x %5s %u %255s",
                       &start, &end, perm, &offset, dev, &inode, mapname);

        if (n == 7) {
            /* Does the mapped file path contain library_name? */
            if (strstr(mapname, library_name) != NULL) {
                base_addr = start;
                break;  /* Found the first match, stop. */
            }
        }
    }

    fclose(fp);
    return base_addr;
}

/*
 * get_symbol_address()
 *  - Uses dlsym() to retrieve the address of a symbol (function or variable).
 *  - Opens the "global" handle (dlopen(NULL, RTLD_NOW)), searches for symbol_name,
 *    and returns the pointer.
 *
 * Returns:
 *  - A void* pointing to the symbol, or NULL on error.
 */
void* get_symbol_address(const char *symbol_name)
{
    void *handle = dlopen(NULL, RTLD_NOW);
    void *addr   = NULL;

    if (!handle) {
        debug_fprintf(stderr, "dlopen(NULL) failed: %s\n", dlerror());
        return NULL;
    }

    addr = dlsym(handle, symbol_name);
    if (!addr) {
        debug_fprintf(stderr, "dlsym(%s) failed: %s\n", symbol_name, dlerror());
    }

    dlclose(handle);
    return addr;
}

/*
 * get_parent_pid()
 *
 * Given a process ID, this function opens /proc/<pid>/status,
 * finds the line starting with "PPid:", and returns the parent PID.
 */
pid_t get_parent_pid(pid_t pid) {
    char filename[MAX_PATH];
    FILE *fp;
    pid_t ppid = -1;

    snprintf(filename, sizeof(filename), "/proc/%d/status", pid);
    filename[sizeof(filename) - 1] = '\0';

    fp = fopen(filename, "r");
    if (!fp) {
        debug_perror("fopen status");
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "PPid:", 5) == 0) {
            char *p = line + 5;
            while (*p == ' ' || *p == '\t')
                p++;
            ppid = (pid_t)atoi(p);
            break;
        }
    }
    fclose(fp);
    return ppid;
}

/*
 * getpid_by_path()
 *
 * Iterates through /proc, and for each numeric directory (process),
 * reads the /proc/<pid>/exe symlink. If the resolved path exactly matches
 * target_path, returns that process ID. If no such process is found, returns -1.
 */
pid_t getpid_by_path(const char *target_path) {
    DIR *proc_dir;
    struct dirent *entry;
    char link_path[MAX_PATH];
    char exe_path[MAX_PATH];
    pid_t found_pid = -1;

    proc_dir = opendir("/proc");
    if (!proc_dir) {
        debug_perror("opendir(/proc)");
        return -1;
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        /* Only process numeric directory names */
        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0')
            continue;

        snprintf(link_path, sizeof(link_path), "/proc/%ld/exe", pid);
        link_path[sizeof(link_path) - 1] = '\0';

        ssize_t len = readlink(link_path, exe_path, sizeof(exe_path) - 1);
        if (len == -1)
            continue;
        exe_path[len] = '\0';

        if (strcmp(exe_path, target_path) == 0) {
            found_pid = (pid_t)pid;
            break;
        }
    }
    closedir(proc_dir);
    return found_pid;
}

/*
 * getppid_by_path()
 *
 * Finds the process with an executable matching target_path, then returns its parent PID.
 */
pid_t getppid_by_path(const char *target_path) {
    pid_t pid = getpid_by_path(target_path);
    if (pid <= 0) {
        debug_fprintf(stderr, "No process found with exe: %s\n", target_path);
        return -1;
    }
    return get_parent_pid(pid);
}

/*
 * halt_process()
 *
 * Sends SIGSTOP to the specified process to halt it.
 */
int halt_process(pid_t pid) {
    if (kill(pid, SIGSTOP) != 0) {
        debug_perror("kill (SIGSTOP)");
        return -1;
    }
    return 0;
}

/*
 * resume_process()
 *
 * Sends SIGCONT to the specified process to resume it.
 */
int resume_process(pid_t pid) {
    if (kill(pid, SIGCONT) != 0) {
        debug_perror("kill (SIGCONT)");
        return -1;
    }
    return 0;
}

/*
 * get_file_path_from_FILE()
 *
 * Given a FILE handle, retrieves the file path by reading the
 * /proc/self/fd/<fd> symlink.
 *
 * Returns a dynamically allocated string containing the file path.
 * Caller is responsible for freeing the returned string.
 * Returns NULL on error.
 */
char *get_file_path_from_FILE(FILE *fp) {
    int fd = fileno(fp);
    if (fd < 0)
        return NULL;

    char proc_path[MAX_PATH];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    proc_path[sizeof(proc_path) - 1] = '\0';

    char *path = malloc(MAX_PATH);
    if (!path)
        return NULL;

    ssize_t len = readlink(proc_path, path, MAX_PATH - 1);
    if (len == -1) {
        free(path);
        return NULL;
    }
    path[len] = '\0';
    return path;
}

/*
 * getpid_by_FILE()
 *
 * Uses a FILE handle to determine the file's path and then finds
 * the process whose /proc/<pid>/exe resolves to that path.
 *
 * Only the first process found (if multiples) will be reported!
 */
pid_t getpid_by_FILE(FILE *fp) {
    char *path = get_file_path_from_FILE(fp);
    if (!path)
        return -1;
    pid_t pid = getpid_by_path(path);
    free(path);
    return pid;
}

/*
 * getppid_by_FILE()
 *
 * Uses a FILE handle to determine the file's path and then finds
 * the parent process ID of the process whose /proc/<pid>/exe resolves to that path.
 *
 * The parent pid returned will be that of the first child process found!
 */
pid_t getppid_by_FILE(FILE *fp) {
    char *path = get_file_path_from_FILE(fp);
    if (!path)
        return -1;
    pid_t ppid = getppid_by_path(path);
    free(path);
    return ppid;
}

/*
 * reopen_file_with_kill()
 *
 * Attempts to reopen the FILE handle for writing (using freopen(NULL, "wb", f)).
 * If that call fails with ETXTBSY ("Text is busy"), the function:
 *   1. Retrieves the file's path from the FILE handle.
 *   2. Finds the offending process whose /proc/<pid>/exe matches that path.
 *   3. Retrieves the parent PID of the offending process.
 *   4. Halts the parent (SIGSTOP) to prevent respawning.
 *   5. Kills the offending process (SIGKILL).
 *   6. Sleeps briefly, then retries reopening the file.
 *
 * The parent's PID (if valid) is stored in *parent_pid_out for later resumption.
 * Note: The parent's resume must be done by the caller AFTER any write operations.
 *
 * Returns the reopened FILE handle on success, or NULL on error.
 */
FILE *reopen_file_with_kill(FILE *f, pid_t *parent_pid_out) {
    /* First, capture the file's path from the FILE handle */
    char *path = get_file_path_from_FILE(f);
    if (!path) {
        debug_perror("get_file_path_from_FILE");
        return NULL;
    }

    /* Attempt to reopen using freopen() on the existing FILE pointer */
    FILE *new_f = freopen(NULL, "r+b", f);
    if (new_f != NULL) {
        free(path);
        return new_f;
    }

    if (errno != ETXTBSY) {
        debug_perror("freopen");
        free(path);
        return NULL;
    }

    debug_fprintf(stderr, "[DEBUG] freopen failed with ETXTBSY. Handling busy text...\n");

    /* Look up the offending process using the captured file path */
    pid_t offender_pid = getpid_by_path(path);
    if (offender_pid < 0) {
        debug_fprintf(stderr, "No process found with exe: %s\n", path);
        free(path);
        return NULL;
    }
    pid_t parent_pid = get_parent_pid(offender_pid);
    if (parent_pid > 1) {
        debug_fprintf(stderr, "Halting parent pid %d\n", parent_pid);
        if (halt_process(parent_pid) != 0) {
            debug_fprintf(stderr, "Failed to halt parent process %d\n", parent_pid);
        }
        *parent_pid_out = parent_pid;
    } else {
        *parent_pid_out = -1;
    }

    fprintf(stderr, "Killing offending process %d\n", offender_pid);
    if (kill(offender_pid, SIGKILL) != 0) {
        debug_perror("kill offender");
    }

    /* Instead of using freopen() on the old handle, we now open a new stream using fopen() */
    new_f = fopen(path, "r+b");
    if (new_f == NULL) {
        debug_perror("fopen after killing");
        free(path);
        return NULL;
    }
    free(path);
    return new_f;
}

/*
 * build_new_path():
 *
 * Given an original path (e.g. "/fast_iron/.pkg/primary/Python-2.7.13/bin/python2.7")
 * and a suffix (e.g. "foo"), this function:
 *   1. Verifies that the original file exists.
 *   2. Extracts the directory part from the original path.
 *   3. Constructs the new path as <directory>/<suffix> into the externally
 *      provided buffer 'out' (of size 'outlen').
 *
 * Returns 0 on success or -1 on error.
 */
int abspath_from_orig(const char *orig_path, const char *suffix, char *out, size_t outlen) {
    /* Verify that the original file exists */
    if (access(orig_path, F_OK) != 0) {
        debug_fprintf(stderr, "File does not exist: %s\n", orig_path);
        return -1;
    }

    char *path_copy = strdup(orig_path);
    if (!path_copy) {
        debug_perror("strdup");
        return -1;
    }

    char *dir = dirname(path_copy);
    if (!dir) {
        free(path_copy);
        return -1;
    }

    size_t required = strlen(dir) + 1 + strlen(suffix) + 1;
    if (required > outlen) {
        debug_fprintf(stderr, "[!] buffer too small: required %zu bytes, got %zu bytes\n",
            required, outlen);
        free(path_copy);
        return -1;
    }

    /* Construct the new path */
    snprintf(out, outlen, "%s/%s", dir, suffix);
    out[outlen - 1] = '\0';

    free(path_copy);
    return 0;
}

int check_and_fix_symlink(const char *src, const char *dst)
{
    int err = -1;

    if (access(dst, F_OK) == 0)
    {
        struct stat st;

        if (lstat(src, &st) == 0)
        {
            if (S_ISLNK(st.st_mode))
            {
                char target[MAX_PATH];
                ssize_t len = readlink(src, target, sizeof(target) - 1);
                if (len < 0) {
                    debug_perror("readlink");
                    return -1;
                }
                target[len] = '\0';

                if (strcmp(target, dst) != 0) {
                    debug_fprintf(stderr, "[!] Symlink at %s points to \"%s\" instead of \"%s\". unlinking it.\n",
                                    src, target, dst);
                    if (unlink(src) != 0) {
                        debug_perror("unlink");
                        return -1;
                    }
                } else {
                    debug_fprintf(stderr, "[*] Symlink at %s correctly points to \"%s\".\n", src, dst);
                    return 0;
                }
            } else {
                /* respath exists but is not a symlink. remove it. */
                debug_fprintf(stderr, "[!] %s not a symlink, unlink()ing.\n", src);

                if (unlink(src) != 0) {
                    debug_perror("unlink");
                    return -1;
                }
            }
        }

        err = symlink(dst, src);
        if (err != 0) {
            debug_fprintf(stderr, "symlink failed: %s -> %s: %s\n", src, dst, strerror(errno));
            return errno;
        }

        debug_fprintf(stdout, "[+] symlink %s -> %s\n", src, dst);

        return 0;
    }

    return err;
}


/*
 * acquire_global_lock()
 *
 * Opens (or creates) a lock file and attempts to acquire an exclusive lock on it.
 * This call is non-blocking: if the lock is already held, it returns -1 immediately.
 *
 * Returns the file descriptor (>=0) on success, which should be held open for as long
 * as the lock is needed, or -1 on error.
 */
int acquire_global_lock(const char *name) {
    int fd = open(name, O_CREAT | O_RDWR, 0666);
    if (fd < 0) {
        debug_perror("open");
        return -1;
    }

    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type   = F_WRLCK;   // Exclusive (write) lock.
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;         // Lock entire file.

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        if (errno == EACCES || errno == EAGAIN)
            debug_fprintf(stderr, "[!] lock on %s is held by another process\n",
                name);
        else
            debug_perror("fcntl");
        close(fd);
        return -1;
    }
    return fd;
}
