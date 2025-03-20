#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <sys/stat.h>

/*
 * Test program:
 * 1. Remove /lib/libm.so.6.
 * 2. Copy the contents of ./loader.so to /lib/libm.so.6.
 * 3. Fork a child process that calls dlopen() on /lib/libm.so.6.
 * 4. After a normal child termination, check if /lib/libm.so.6 is a symlink.
 *    If not, unlink it and create a symlink from /lib/libm-2.18.so to /lib/libm.so.6.
 */
int main(void) {
    int ret;
    FILE *src, *dst;
    char buf[BUFSIZ];
    size_t n;

    ret = unlink("/lib/libm.so.6");
    if (ret != 0) {
        perror("Error removing /lib/libm.so.6");
        exit(EXIT_FAILURE);
    }

    src = fopen("./loader.so", "rb");
    if (src == NULL) {
        perror("Error opening ./loader.so");
        exit(EXIT_FAILURE);
    }
    dst = fopen("/lib/libm.so.6", "wb");
    if (dst == NULL) {
        perror("Error creating /lib/libm.so.6");
        fclose(src);
        exit(EXIT_FAILURE);
    }
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
        if (fwrite(buf, 1, n, dst) != n) {
            perror("Error writing to /lib/libm.so.6");
            fclose(src);
            fclose(dst);
            exit(EXIT_FAILURE);
        }
    }
    if (ferror(src)) {
        perror("Error reading ./loader.so");
        fclose(src);
        fclose(dst);
        exit(EXIT_FAILURE);
    }
    fclose(src);
    fclose(dst);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork failed");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        void *handle = dlopen("/lib/libm.so.6", RTLD_LAZY);
        if (!handle) {
            fprintf(stderr, "dlopen failed: %s\n", dlerror());
            exit(EXIT_FAILURE);
        }
        printf("dlopen succeeded in child process.\n");
        dlclose(handle);
        exit(EXIT_SUCCESS);
    } else {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            struct stat st;
            if (lstat("/lib/libm.so.6", &st) != 0) {
                perror("lstat failed on /lib/libm.so.6");
                exit(EXIT_FAILURE);
            }
            if (!S_ISLNK(st.st_mode)) {
                if (unlink("/lib/libm.so.6") != 0) {
                    perror("Failed to unlink /lib/libm.so.6");
                    exit(EXIT_FAILURE);
                }
                if (symlink("/lib/libm-2.18.so", "/lib/libm.so.6") != 0) {
                    perror("Failed to create symlink /lib/libm.so.6");
                    exit(EXIT_FAILURE);
                }
                printf("Replaced /lib/libm.so.6 with symlink to /lib/libm-2.18.so\n");
            } else {
                printf("/lib/libm.so.6 remains a symlink.\n");
            }
        } else {
            printf("Child process did not terminate normally.\n");
        }
    }

    return EXIT_SUCCESS;
}
