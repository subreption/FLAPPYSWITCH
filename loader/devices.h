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

#ifndef _DEVICES_H
#define _DEVICES_H

/* Device type definitions */
#define SYS_CPLD         0
#define EEPROM           1
#define PCA9559          2
#define FPGA_MAIN        3

#define MAX_CPLD_REGISTER   0x90

/* Registers for the system CPLD */
#define SYS_CPLD_RESET_CAUSE_REG        0x0a
#define SYS_CPLD_BOOT_LOC               0x0b
#define SYS_CPLD_PRI_FAIL_REC           0x0c
#define SYS_CPLD_SEC_FAIL_REC           0x0d
#define SYS_CPLD_SPI_CS                 0x0e
#define SYS_CPLD_RESET_CTRL_1           0x30
#define SYS_CPLD_RESET_CTRL_2           0x31
#define SYS_CPLD_WP_REG                 0x34
#define SYS_CPLD_WDT_CTRL_REG           0x40

#define PUBLIC_RELEASE_PLATFORM         "MINIONS"

typedef struct {
    int devtype;
    int address;
    int bus;
} device_config_t;

typedef struct {
    const char *model_name;     /* Platform name (ex. "MINIONS") */
    device_config_t cpld;       /* SYS_CPLD configuration */
    device_config_t eeprom;     /* EEPROM configuration */
    device_config_t pca9559;    /* PCA9559 configuration */
    device_config_t fpga;       /* MAINBOARD_FPGA configuration */
} device_model_config_t;

/*
 * API: select_model_config
 *
 * Returns the device model configuration for the target device specified by model name.
 *
 * Parameters:
 *   model_name - string representing the model name (ex. "MINIONS")
 *
 * Returns:
 *   Pointer to the device_model_config_t structure for that model, or NULL if the model is not supported.
 */
const device_model_config_t* select_model_config(const char *model_name);

int syscpld_read(const device_model_config_t *modelcfg,
    unsigned char *buf, unsigned int len);

int syscpld_write_reg(const device_model_config_t *modelcfg,
    int reg, unsigned char val);

int eeprom_read(const device_model_config_t *modelcfg,
    int offset, unsigned char *buf, size_t len);

void device_powercycle(const device_model_config_t *modelcfg);

#endif /* DEVICES_H */
