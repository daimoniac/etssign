/*
 * etssign - CLI for computing/checking/writing ETS ProjectStore
 * .ets5hash companion files. ETS 5 and ETS 6 share this suffix and
 * recipe. See etssign.h for the algorithm.
 *
 * Usage:
 *   etssign hash  --guid GUID --id ID FILE
 *   etssign mask  --guid GUID --id ID
 *   etssign check --guid GUID --id ID FILE [FILE...]
 *   etssign write --guid GUID --id ID FILE [FILE...]
 *   etssign check STORE_DIR [FILE...]
 *   etssign write STORE_DIR [FILE...]
 *
 * In the STORE_DIR form, Id and Guid are read from STORE_DIR/P. With no
 * FILE arguments, every file in STORE_DIR that already has a sibling
 * "<name>.ets5hash" is processed. The "<id>.store" file is a different,
 * unrelated check and is never touched.
 */
#define _POSIX_C_SOURCE 200809L

#include "etssign.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void die(const char *msg) {
    fprintf(stderr, "etssign: %s\n", msg);
    exit(1);
}

static char *read_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) die("cannot open file");
    if (fseek(f, 0, SEEK_END) != 0) die("cannot seek file");
    long size = ftell(f);
    if (size < 0) die("cannot tell file size");
    rewind(f);
    char *buf = malloc((size_t)size + 1);
    if (!buf) die("out of memory");
    if (size > 0 && fread(buf, 1, (size_t)size, f) != (size_t)size) die("short read");
    buf[size] = '\0';
    fclose(f);
    *len_out = (size_t)size;
    return buf;
}

static int path_join(char *out, size_t out_size, const char *dir, const char *name) {
    return snprintf(out, out_size, "%s/%s", dir, name) < (int)out_size ? 0 : -1;
}

static int has_suffix(const char *s, const char *suffix) {
    size_t ls = strlen(s), lx = strlen(suffix);
    return ls >= lx && strcmp(s + ls - lx, suffix) == 0;
}

/* Project identity, either given explicitly or read from STORE_DIR/P. */
typedef struct {
    char id[64];
    char guid[64];
} project_t;

static void load_project_from_store(const char *store_dir, project_t *out) {
    char p_path[4096];
    if (path_join(p_path, sizeof(p_path), store_dir, "P") != 0) die("store path too long");
    size_t len;
    char *data = read_file(p_path, &len);
    if (ets_read_project_p(data, len, out->id, sizeof(out->id), out->guid, sizeof(out->guid)) != 0) {
        die("could not find Proj/@Id or ProjInfo/@Guid in STORE_DIR/P");
    }
    free(data);
}

static uint16_t require_mask(const project_t *proj) {
    uint16_t mask;
    if (ets_mask(proj->guid, proj->id, &mask) != 0) {
        die("malformed project GUID");
    }
    return mask;
}

static int check_one(const char *file_path, uint16_t mask) {
    size_t len;
    char *data = read_file(file_path, &len);
    char got[ETSSIGN_B64_LEN];
    ets_hash_b64((const uint8_t *)data, len, mask, got);
    free(data);

    char hash_path[4096];
    snprintf(hash_path, sizeof(hash_path), "%s.ets5hash", file_path);
    size_t elen;
    char *expected = read_file(hash_path, &elen);
    while (elen > 0 && (expected[elen - 1] == '\n' || expected[elen - 1] == '\r')) {
        expected[--elen] = '\0';
    }

    int ok = strcmp(got, expected) == 0;
    printf("%s %s\n", ok ? "ok  " : "fail", file_path);
    if (!ok) {
        printf("     stored   %s\n", expected);
        printf("     computed %s\n", got);
    }
    free(expected);
    return ok;
}

static void write_one(const char *file_path, uint16_t mask) {
    size_t len;
    char *data = read_file(file_path, &len);
    char b64[ETSSIGN_B64_LEN];
    ets_hash_b64((const uint8_t *)data, len, mask, b64);
    free(data);

    char hash_path[4096];
    snprintf(hash_path, sizeof(hash_path), "%s.ets5hash", file_path);
    FILE *f = fopen(hash_path, "wb");
    if (!f) die("cannot write .ets5hash");
    fputs(b64, f);
    fclose(f);
    printf("wrote %s\n", hash_path);
}

/* Lists files in store_dir that already have a sibling .ets5hash. */
static int discover_hashed_files(const char *store_dir, char ***out_paths) {
    DIR *d = opendir(store_dir);
    if (!d) die("cannot open STORE_DIR");
    char **paths = NULL;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (has_suffix(entry->d_name, ".ets5hash")) continue;
        char candidate_hash[4096];
        snprintf(candidate_hash, sizeof(candidate_hash), "%s/%s.ets5hash", store_dir, entry->d_name);
        struct stat st;
        if (stat(candidate_hash, &st) != 0) continue;

        char full[4096];
        path_join(full, sizeof(full), store_dir, entry->d_name);
        paths = realloc(paths, (size_t)(count + 1) * sizeof(char *));
        paths[count++] = strdup(full);
    }
    closedir(d);
    *out_paths = paths;
    return count;
}

static int cmd_mask(int argc, char **argv) {
    const char *guid = NULL, *id = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--guid") == 0 && i + 1 < argc) guid = argv[++i];
        else if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) id = argv[++i];
    }
    if (!guid || !id) die("mask requires --guid GUID --id ID");
    uint16_t mask;
    if (ets_mask(guid, id, &mask) != 0) die("malformed GUID");
    printf("%u (0x%x)\n", mask, mask);
    return 0;
}

static int cmd_hash(int argc, char **argv) {
    const char *guid = NULL, *id = NULL, *file = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--guid") == 0 && i + 1 < argc) guid = argv[++i];
        else if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) id = argv[++i];
        else file = argv[i];
    }
    if (!guid || !id || !file) die("hash requires --guid GUID --id ID FILE");
    uint16_t mask;
    if (ets_mask(guid, id, &mask) != 0) die("malformed GUID");
    size_t len;
    char *data = read_file(file, &len);
    char b64[ETSSIGN_B64_LEN];
    ets_hash_b64((const uint8_t *)data, len, mask, b64);
    free(data);
    printf("%s\n", b64);
    return 0;
}

/* Shared by `check`/`write` in both the --guid/--id form and the STORE_DIR
 * form. Returns the resolved project, the directory to search for files
 * when none are given, and the index in argv where FILE arguments start. */
static int resolve_project_and_files(int argc, char **argv, project_t *proj,
                                      char *store_dir_out, size_t store_dir_size,
                                      int *files_start) {
    const char *guid = NULL, *id = NULL;
    int i = 0;
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--guid") == 0 && i + 1 < argc) { guid = argv[++i]; continue; }
        if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) { id = argv[++i]; continue; }
        break;
    }
    if (guid && id) {
        snprintf(proj->guid, sizeof(proj->guid), "%s", guid);
        snprintf(proj->id, sizeof(proj->id), "%s", id);
        store_dir_out[0] = '\0';
        *files_start = i;
        if (i >= argc) die("--guid/--id form requires at least one FILE");
        return 0;
    }
    if (i >= argc) die("expected STORE_DIR or --guid/--id FILE...");
    snprintf(store_dir_out, store_dir_size, "%s", argv[i]);
    load_project_from_store(store_dir_out, proj);
    *files_start = i + 1;
    return 0;
}

static int cmd_check(int argc, char **argv) {
    project_t proj;
    char store_dir[4096];
    int files_start;
    resolve_project_and_files(argc, argv, &proj, store_dir, sizeof(store_dir), &files_start);
    uint16_t mask = require_mask(&proj);

    int all_ok = 1;
    if (files_start < argc) {
        for (int i = files_start; i < argc; i++) {
            char full[4096];
            if (store_dir[0] && argv[i][0] != '/') {
                path_join(full, sizeof(full), store_dir, argv[i]);
            } else {
                snprintf(full, sizeof(full), "%s", argv[i]);
            }
            all_ok &= check_one(full, mask);
        }
    } else {
        char **paths;
        int n = discover_hashed_files(store_dir, &paths);
        for (int i = 0; i < n; i++) {
            all_ok &= check_one(paths[i], mask);
            free(paths[i]);
        }
        free(paths);
    }
    return all_ok ? 0 : 1;
}

static int cmd_write(int argc, char **argv) {
    project_t proj;
    char store_dir[4096];
    int files_start;
    resolve_project_and_files(argc, argv, &proj, store_dir, sizeof(store_dir), &files_start);
    uint16_t mask = require_mask(&proj);

    if (files_start < argc) {
        for (int i = files_start; i < argc; i++) {
            char full[4096];
            if (store_dir[0] && argv[i][0] != '/') {
                path_join(full, sizeof(full), store_dir, argv[i]);
            } else {
                snprintf(full, sizeof(full), "%s", argv[i]);
            }
            write_one(full, mask);
        }
    } else {
        char **paths;
        int n = discover_hashed_files(store_dir, &paths);
        for (int i = 0; i < n; i++) {
            write_one(paths[i], mask);
            free(paths[i]);
        }
        free(paths);
    }
    return 0;
}

static int self_test(void) {
    uint16_t mask;
    if (ets_mask("00000000-0000-0000-0000-000000000001", "P-0001", &mask) != 0) {
        fprintf(stderr, "self-test: bad guid parse\n");
        return 1;
    }
    char b64[ETSSIGN_B64_LEN];
    ets_hash_b64((const uint8_t *)"ets5hash", 8, mask, b64);
    if (mask != 319 || strcmp(b64, "TnwiqUYt9qo22B/u9TAwSUUcPTM=") != 0) {
        fprintf(stderr, "self-test failed: mask=%u hash=%s\n", mask, b64);
        return 1;
    }
    printf("etssign self-test OK\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--self-test") == 0) {
        return self_test();
    }
    if (argc < 2) die("usage: etssign hash|mask|check|write ... (see source header)");

    const char *cmd = argv[1];
    int rest_argc = argc - 2;
    char **rest_argv = argv + 2;

    if (strcmp(cmd, "mask") == 0) return cmd_mask(rest_argc, rest_argv);
    if (strcmp(cmd, "hash") == 0) return cmd_hash(rest_argc, rest_argv);
    if (strcmp(cmd, "check") == 0) return cmd_check(rest_argc, rest_argv);
    if (strcmp(cmd, "write") == 0) return cmd_write(rest_argc, rest_argv);
    die("unknown command (expected hash, mask, check, or write)");
    return 1;
}
