#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        fprintf(stderr, "Example: %s curl ipinfo.io/json\n", argv[0]);
        return 1;
    }

    char exe_path[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (n < 0) {
        perror("readlink /proc/self/exe");
        return 1;
    }
    exe_path[n] = '\0';

    /* Replace binary name with libdused.so */
    char *last_slash = strrchr(exe_path, '/');
    if (last_slash)
        last_slash[1] = '\0';
    else
        exe_path[0] = '\0';

    char lib_path[PATH_MAX];
    const char *lib_env = getenv("DUSED_LIB");
    if (lib_env) {
        strncpy(lib_path, lib_env, sizeof(lib_path) - 1);
        lib_path[sizeof(lib_path) - 1] = '\0';
    } else {
        if (snprintf(lib_path, sizeof(lib_path), "%slibdused.so", exe_path) >= (int)sizeof(lib_path)) {
            fprintf(stderr, "dused: path to libdused.so too long\n");
            return 1;
        }
        if (access(lib_path, R_OK) != 0) {
            fprintf(stderr, "dused: cannot find %s (run from build directory or set DUSED_LIB)\n", lib_path);
            return 1;
        }
    }

    if (setenv("LD_PRELOAD", lib_path, 1) != 0) {
        perror("setenv LD_PRELOAD");
        return 1;
    }

    execvp(argv[1], &argv[1]);
    perror(argv[1]);
    return 127;
}
