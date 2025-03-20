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
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <errno.h>
#include "devices.h"
#include "debug.h"

/* limiting public release to ICX7150/MINIONS platform */
static const device_model_config_t config_ICX7150 = {
    .model_name = "MINIONS",
    .cpld     = { SYS_CPLD,       0x33,  0 },
    .eeprom   = { EEPROM,         0x50,  0 }, /* can also be 0x52! */
    .pca9559  = { PCA9559,        0x20,  0 },
    .fpga     = { FPGA_MAIN,      0x40,  1 }
};

static const device_model_config_t *supported_models[] = {
    &config_ICX7150,
    NULL
};

/* EEPROM definitions */
#define EEPROM_FIPS_BIT_OFFSET   0xA5
#define EEPROM_FIPS_BIT_SET      0xA8
#define EEPROM_FIPS_BIT_CLEAR    0xA0

/*
 * get_device_config: Selects the device configuration within a model based on the device type.
 */
static const device_config_t* get_device_config(const device_model_config_t *model_config, int devtype)
{
    if (!model_config) {
        return NULL;
    }

    switch (devtype) {
        case SYS_CPLD:
            return &model_config->cpld;
        case EEPROM:
            return &model_config->eeprom;
        case PCA9559:
            return &model_config->pca9559;
        case FPGA_MAIN:
            return &model_config->fpga;
        default:
            return NULL;
    }
}

/*
 * select_model_config: Iterates over the supported models to find a match.
 *
 * Parameters:
 *   model_name - string representing the model name (ex. "MINIONS")
 *
 * Returns:
 *   Pointer to the device_model_config_t structure for that model, or NULL if the model is not supported.
 */
const device_model_config_t* select_model_config(const char *model_name)
{
    int i;

    if (!model_name) {
        return NULL;
    }

    for (i = 0; supported_models[i] != NULL; i++) {
        if (strcmp(model_name, supported_models[i]->model_name) == 0) {
            return supported_models[i];
        }
    }

    return NULL; /* Model not recognized */
}

static int _i2c_write(int fd, int addr, int offset, unsigned char *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        struct i2c_rdwr_ioctl_data packets;
        struct i2c_msg message;
        unsigned char buf[2];

        buf[0] = offset;
        buf[1] = data[i];

        message.addr  = addr;
        message.flags = 0;
        message.len   = 2;
        message.buf   = buf;

        packets.msgs  = &message;
        packets.nmsgs = 1;

        if (ioctl(fd, I2C_RDWR, &packets) < 0) {
            perror("I2C_RDWR ioctl (write)");
            return -1;
        }
    }

    return 0;
}

static int _i2c_read(int fd, int addr, int offset, unsigned char *data, int len)
{
    unsigned char off = offset;
    struct i2c_rdwr_ioctl_data packets;
    struct i2c_msg messages[2];

    messages[0].addr  = addr;
    messages[0].flags = 0;
    messages[0].len   = 1;
    messages[0].buf   = &off;

    messages[1].addr  = addr;
    messages[1].flags = I2C_M_RD;
    messages[1].len   = len;
    messages[1].buf   = data;

    packets.msgs  = messages;
    packets.nmsgs = 2;

    if (ioctl(fd, I2C_RDWR, &packets) < 0) {
        debug_perror("I2C_RDWR ioctl (read)");
        return -1;
    }
    return 0;
}

static int device_rw(const device_model_config_t *modelcfg, int devtype, int offset, unsigned char *val, int write, int len)
{
    int err = 0;
    char devpath[20];
    int fd;
    const device_config_t *devcfg;

    devcfg =  get_device_config(modelcfg, devtype);
    if (devcfg == NULL) {
        debug_fprintf(stderr, "failed to get devconfig for %d in %s\n", devtype,
            modelcfg->model_name);
        return -1;
    }

    snprintf(devpath, sizeof(devpath), "/dev/i2c-%d", devcfg->bus);
    fd = open(devpath, O_RDWR);
    if (fd < 0) {
        debug_perror("open");
        return -1;
    }

    if (ioctl(fd, I2C_SLAVE, devcfg->address) < 0) {
        debug_perror("ioctl I2C_SLAVE");
        close(fd);
        return -1;
    }

    if (write) {
        err = _i2c_write(fd, devcfg->address, offset, val, len);
        if (err != 0) {
            debug_fprintf(stderr, "I2C Write: addr 0x%x, bus %d, offset 0x%x, len %d\n",
                    devcfg->address, devcfg->bus, offset, len);
        }
    } else {
        err = _i2c_read(fd, devcfg->address, offset, val, len);
        if (err != 0) {
            debug_fprintf(stderr, "I2C Read Failure: addr 0x%x, bus %d, offset 0x%x, len %d\n",
                    devcfg->address, devcfg->bus, offset, len);
        }
    }

    close(fd);

    return err;
}

static int chunked_read(const device_model_config_t *modelcfg, int device, int offset, unsigned char *buf, size_t len)
{
    int err = 0;
    size_t remaining, chunk;
    int current_offset;
    unsigned char *current_buf;

    if (!modelcfg || !buf) {
        debug_fprintf(stderr, "[!] NULL model configuration or buffer pointer\n");
        return -1;
    }

    if (offset < 0) {
        debug_fprintf(stderr, "[!] Negative offset %d\n", offset);
        return -1;
    }

    if (len == 0)
        return 0;

    remaining = len;
    current_offset = offset;
    current_buf = buf;

    /* FIFO size is 64 bytes, set another maximum per transfer */
    while (remaining > 0) {
        chunk = (remaining > 24) ? 24 : remaining;

        err = device_rw(modelcfg, device, current_offset, current_buf, 0, chunk);
        if (err) {
            debug_fprintf(stderr, "[!] error while reading dev %d offset %d\n",
                device, current_offset);
            return err;
        }
        remaining    -= chunk;
        current_offset += chunk;
        current_buf  += chunk;
    }

    return 0;
}

int eeprom_read(const device_model_config_t *modelcfg, int offset, unsigned char *buf, size_t len)
{
    if (!modelcfg || !buf) {
        debug_fprintf(stderr, "[!] NULL model configuration or buffer pointer\n");
        return -1;
    }

    if (offset < 0) {
        debug_fprintf(stderr, "[!] Negative offset %d\n", offset);
        return -1;
    }

    if (len == 0)
        return 0;

    if ((unsigned int)(offset + len) > 255) {
        debug_fprintf(stderr, "[!] offset %d and len %zu will exceed EEPROM max read size\n",
                      offset, len);
        return -1;
    }

    return chunked_read(modelcfg, EEPROM, offset, buf, len);
}

int syscpld_read(const device_model_config_t *modelcfg, unsigned char *buf, unsigned int len)
{
    if (!modelcfg || !buf) {
        debug_fprintf(stderr, "[!] NULL model configuration or buffer pointer\n");
        return -1;
    }

    if (len < MAX_CPLD_REGISTER)
        return -1;

    return chunked_read(modelcfg, SYS_CPLD, 0, buf, len);
}

int syscpld_write_reg(const device_model_config_t *modelcfg, int reg, unsigned char val)
{
    int err;
    unsigned char tmp;

    if (!modelcfg) {
        debug_fprintf(stderr, "[!] NULL model configuration\n");
        return -1;
    }

    if (reg > MAX_CPLD_REGISTER)
        return -1;

    tmp = val;

    err = device_rw(modelcfg, SYS_CPLD, reg, &tmp, 1, sizeof(unsigned char));
    if (err) {
        debug_fprintf(stderr, "[!] error writing to system cpld reg %d\n", reg);
        return err;
    }

    return err;
}

void device_powercycle(const device_model_config_t *modelcfg)
{
    int err;
    unsigned char regs[MAX_CPLD_REGISTER];

    err = syscpld_read(modelcfg, (unsigned char *) &regs, sizeof(regs));
    if (err < 0) {
        debug_fprintf(stderr, "[!] failed to read system CPLD regs\n");
        return;
    }

    regs[SYS_CPLD_WDT_CTRL_REG] |= 0x80;

    /* issue powercycle via control register 2 */
    syscpld_write_reg(modelcfg, SYS_CPLD_WDT_CTRL_REG, regs[SYS_CPLD_WDT_CTRL_REG]);
    syscpld_write_reg(modelcfg, SYS_CPLD_RESET_CTRL_2, 0x7f);
}

#ifdef DEVICES_TEST_MAIN
/*
 * hexdump - Print a hex and ASCII dump of the given data.
 *
 * Parameters:
 *   data - Pointer to the data to be dumped.
 *   len  - Length of the data in bytes.
 */
void hexdump(const void *data, size_t len)
{
    const unsigned char *bytes = (const unsigned char *)data;
    size_t i, j;

    for (i = 0; i < len; i += 16) {
        /* Print offset */
        printf("%08lx  ", (unsigned long)i);

        /* Print hex bytes */
        for (j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", bytes[i + j]);
            else
                printf("   ");

            if (j == 7)
                printf(" ");
        }

        /* Print ASCII representation */
        printf(" |");
        for (j = 0; j < 16; j++) {
            if (i + j < len) {
                unsigned char ch = bytes[i + j];
                printf("%c", isprint(ch) ? ch : '.');
            } else {
                printf(" ");
            }
        }
        printf("|\n");
    }
}

int main(void)
{
    unsigned char magic[] = { 0xca, 0x95 };
    unsigned char buf[128];
    const device_model_config_t *modelcfg;
    unsigned char value;
    int err;
    int  i;

    modelcfg = select_model_config(PUBLIC_RELEASE_PLATFORM);

    printf("[*] Reading EEPROM first:\n");

    err = eeprom_read(modelcfg, 0, &buf, sizeof(buf));

    hexdump(buf, sizeof(buf));

    return err;
}
#endif

