/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2013 Bert Vermeulen <bert@biot.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBSIGROK_HARDWARE_OPENBENCH_LOGIC_SNIFFER_PROTOCOL_H
#define LIBSIGROK_HARDWARE_OPENBENCH_LOGIC_SNIFFER_PROTOCOL_H

#include <stdint.h>
#include <string.h>
#include <glib.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "openbench-logic-sniffer"

#define NUM_TRIGGER_STAGES         4
#define CLOCK_RATE                 SR_MHZ(100)
#define MIN_NUM_SAMPLES            4
#define DEFAULT_SAMPLERATE         SR_KHZ(200)

/* Command opcodes */
#define CMD_RESET                  0x00
#define CMD_RUN                    0x01
#define CMD_ID                     0x02
#define CMD_METADATA               0x04
#define CMD_SET_DIVIDER            0x80
#define CMD_CAPTURE_SIZE           0x81
#define CMD_SET_FLAGS              0x82
#define CMD_CAPTURE_DELAYCOUNT     0x83		/* extension for Pepino */
#define CMD_CAPTURE_READCOUNT      0x84		/* extension for Pepino */
#define CMD_SET_TRIGGER_MASK       0xc0
#define CMD_SET_TRIGGER_VALUE      0xc1
#define CMD_SET_TRIGGER_CONFIG     0xc2

/* Trigger config */
#define TRIGGER_START              (1 << 3)

/* Bit mask used for "set flags" command (0x82) */
/* Take care about bit positions in diagrams, they are inverted. */
#define CAPTURE_FLAG_RLEMODE1            (1 << 15)
#define CAPTURE_FLAG_RLEMODE0            (1 << 14)
#define CAPTURE_FLAG_RESERVED1           (1 << 13)
#define CAPTURE_FLAG_RESERVED0           (1 << 12)
#define CAPTURE_FLAG_INTERNAL_TEST_MODE  (1 << 11)
#define CAPTURE_FLAG_EXTERNAL_TEST_MODE  (1 << 10)
#define CAPTURE_FLAG_SWAP_CHANNELS       (1 << 9)
#define CAPTURE_FLAG_RLE                 (1 << 8)
#define CAPTURE_FLAG_INVERT_EXT_CLOCK    (1 << 7)
#define CAPTURE_FLAG_CLOCK_EXTERNAL      (1 << 6)
#define CAPTURE_FLAG_DISABLE_CHANGROUP_4 (1 << 5)
#define CAPTURE_FLAG_DISABLE_CHANGROUP_3 (1 << 4)
#define CAPTURE_FLAG_DISABLE_CHANGROUP_2 (1 << 3)
#define CAPTURE_FLAG_DISABLE_CHANGROUP_1 (1 << 2)
#define CAPTURE_FLAG_NOISE_FILTER        (1 << 1)
#define CAPTURE_FLAG_DEMUX               (1 << 0)

/* Capture context magic numbers */
#define OLS_NO_TRIGGER (-1)

struct dev_context {
	/* constant device properties: */
	int max_channels;
	uint32_t max_samples;
	uint32_t max_samplerate;
	uint32_t protocol_version;

	/* acquisition-related properties: */
	uint64_t cur_samplerate;
	uint32_t cur_samplerate_divider;
	uint64_t limit_samples;
	uint64_t capture_ratio;
	int trigger_at_smpl;
	uint32_t channel_mask;
	uint32_t trigger_mask[NUM_TRIGGER_STAGES];
	uint32_t trigger_value[NUM_TRIGGER_STAGES];
	int num_stages;
	uint16_t capture_flags;

	unsigned int num_transfers;
	unsigned int num_samples;
	int num_bytes;
	int cnt_bytes;
	int cnt_samples;
	int cnt_samples_rle;

	unsigned int rle_count;
	unsigned char sample[4];
	unsigned char tmp_sample[4];
	unsigned char *raw_sample_buf;
};

SR_PRIV extern const char *ols_channel_names[];

SR_PRIV int send_shortcommand(struct sr_serial_dev_inst *serial,
		uint8_t command);
SR_PRIV int send_longcommand(struct sr_serial_dev_inst *serial,
		uint8_t command, uint8_t *data);
SR_PRIV int ols_send_reset(struct sr_serial_dev_inst *serial);
SR_PRIV void ols_channel_mask(const struct sr_dev_inst *sdi);
SR_PRIV int ols_convert_trigger(const struct sr_dev_inst *sdi);
SR_PRIV struct dev_context *ols_dev_new(void);
SR_PRIV struct sr_dev_inst *get_metadata(struct sr_serial_dev_inst *serial);
SR_PRIV int ols_set_samplerate(const struct sr_dev_inst *sdi,
		uint64_t samplerate);
SR_PRIV void abort_acquisition(const struct sr_dev_inst *sdi);
SR_PRIV int ols_receive_data(int fd, int revents, void *cb_data);

#endif
