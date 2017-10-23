/*
 * This file is part of the libsigrok project.
 *
 * Copyright 2017 Google, Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#include <config.h>
#include <stdint.h>
#include <string.h>
#include <libusb.h>
#include <stdio.h>
#include <errno.h>
#include <math.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"
#include "protocol.h"

/* 'twinkie vbus' command output format */
#define VBUS_FORMAT "VBUS = %d mV ; %d mA"

SR_PRIV int twinkie_start_acquisition(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;
	struct timespec tsample;

	clock_gettime(CLOCK_REALTIME, &tsample);
	devc->vbus_t0 = tsample.tv_nsec + (uint64_t)tsample.tv_sec *1000000000ULL;

	return SR_OK;
}

SR_PRIV int twinkie_init_device(const struct sr_dev_inst *sdi)
{
	(void)sdi;

	return SR_OK;
}

static void finish_acquisition(struct sr_dev_inst *sdi)
{
	struct sr_datafeed_packet packet;
	struct dev_context *devc = sdi->priv;

	/* Terminate session. */
	packet.type = SR_DF_END;
	sr_session_send(sdi, &packet);

	/* Remove fds from polling. */
	usb_source_remove(sdi->session, devc->ctx);

	devc->num_transfers = 0;
	g_free(devc->transfers);
	g_free(devc->convbuffer);
}

static void free_transfer(struct libusb_transfer *transfer)
{
	struct sr_dev_inst *sdi;
	struct dev_context *devc;
	unsigned int i;

	sdi = transfer->user_data;
	devc = sdi->priv;

	g_free(transfer->buffer);
	transfer->buffer = NULL;
	libusb_free_transfer(transfer);

	for (i = 0; i < devc->num_transfers; i++) {
		if (devc->transfers[i] == transfer) {
			devc->transfers[i] = NULL;
			break;
		}
	}

	devc->submitted_transfers--;
	if (devc->submitted_transfers == 0)
		finish_acquisition(sdi);
}

static void export_samples(const struct sr_dev_inst *sdi, size_t cnt)
{
	struct sr_datafeed_packet packet;
	struct sr_datafeed_logic logic;
	struct dev_context *devc = sdi->priv;

	/* export the received data */
	packet.type = SR_DF_LOGIC;
	packet.payload = &logic;
	if (devc->limit_samples &&
	    cnt > devc->limit_samples - devc->sent_samples)
		cnt = devc->limit_samples - devc->sent_samples;
	logic.length = cnt;
	logic.unitsize = 1;
	logic.data = devc->convbuffer;
	sr_session_send(sdi, &packet);
	devc->sent_samples += cnt;
}

static void expand_sample_data(const struct sr_dev_inst *sdi,
			       const uint8_t *src, size_t srccnt)
{
	struct dev_context *devc = sdi->priv;
	int i, f;
	size_t b;
	size_t rdy_samples, left_samples;
	int frames = srccnt / 64;

	for (f = 0; f < frames; f++) {
		int ch = (src[1] >> 4) & 3; /* samples channel number */
		int bit = 1 << ch; /* channel bit mask */
		struct cc_context *cc = devc->cc + ch;
		uint8_t *dest = devc->convbuffer + cc->idx;

		if (ch >= 2) /* only acquires CCx channels */
			continue;

		/* TODO: check timestamp, overflow, sequence number */

		/* skip header, go to edges data */
		src+=4;
		for (i = 0; i < 60; i++,src++)
			if (*src == cc->prev_src) {
				cc->rollbacks++;
			} else {
				uint8_t diff = *src - cc->prev_src;
				int fixup = cc->rollbacks && (((int)*src < (int)cc->prev_src) || (*src == 0xff));
				size_t total = (fixup ? cc->rollbacks - 1 : cc->rollbacks) * 256 + diff;

				if (total + cc->idx > devc->convbuffer_size) {
					sr_warn("overflow %d+%zd/%zd\n",
						cc->idx, total,
						devc->convbuffer_size);
					/* reset current decoding */
					cc->rollbacks = 0;
					break;
				}

				/* insert bits in the buffer */
				if (cc->level)
					for (b = 0 ; b < total ; b++, dest++)
						*dest |= bit;
				else
					dest += total;
				cc->idx += total;

				/* flip level on the next edge */
				cc->level = ~cc->level;

				cc->rollbacks = 0;
				cc->prev_src = *src;
			}
		/* expand repeated rollbacks */
		if (cc->rollbacks > 1) {
			size_t total = 256 * (cc->rollbacks - 1);
			if (total + cc->idx > devc->convbuffer_size) {
				sr_warn("overflow %d+%zd/%zd\n",
					cc->idx, total, devc->convbuffer_size);
				/* reset current decoding */
				total = 0;
			}
			/* insert bits in the buffer */
			if (cc->level)
				for (b = 0 ; b < total ; b++, dest++)
					*dest |= bit ;
			cc->idx += total;
			cc->rollbacks = 1;
		}
	}

	/* samples ready to be pushed (with both channels) */
	rdy_samples = MIN(devc->cc[0].idx, devc->cc[1].idx);
	left_samples = MAX(devc->cc[0].idx, devc->cc[1].idx) - rdy_samples;
	/* skip empty transfer */
	if (rdy_samples == 0)
		return;

	export_samples(sdi, rdy_samples);

	/* clean up what we have sent */
	memmove(devc->convbuffer, devc->convbuffer + rdy_samples, left_samples);
	memset(devc->convbuffer + left_samples, 0, rdy_samples);
	devc->cc[0].idx -= rdy_samples;
	devc->cc[1].idx -= rdy_samples;
}

SR_PRIV void LIBUSB_CALL twinkie_receive_transfer(struct libusb_transfer *transfer)
{
	gboolean packet_has_error = FALSE;
	struct sr_dev_inst *sdi;
	struct dev_context *devc;

	sdi = transfer->user_data;
	devc = sdi->priv;

	/*
	 * If acquisition has already ended, just free any queued up
	 * transfer that come in.
	 */
	if (devc->sent_samples < 0) {
		free_transfer(transfer);
		return;
	}

	if (transfer->status || transfer->actual_length)
		sr_info("receive_transfer(): status %d received %d bytes.",
			transfer->status, transfer->actual_length);

	switch (transfer->status) {
	case LIBUSB_TRANSFER_NO_DEVICE:
		devc->sent_samples = -2;
		free_transfer(transfer);
		return;
	case LIBUSB_TRANSFER_COMPLETED:
	case LIBUSB_TRANSFER_TIMED_OUT: /* We may have received some data though. */
		break;
	default:
		packet_has_error = TRUE;
		break;
	}

	if (transfer->actual_length % 64) {
		sr_err("Bad USB packet size.");
		packet_has_error = TRUE;
	}

	if (transfer->actual_length == 0 || packet_has_error)
		goto resubmit;

	/* decode received edges */
	expand_sample_data(sdi, transfer->buffer, transfer->actual_length);

	if (devc->limit_samples &&
			(uint64_t)devc->sent_samples >= devc->limit_samples) {
		devc->sent_samples = -2;
		free_transfer(transfer);
		return;
	}
resubmit:
	if (libusb_submit_transfer(transfer) != LIBUSB_SUCCESS)
		free_transfer(transfer);
}

static void export_vbus(const struct sr_dev_inst *sdi, int mv, int ma)
{
	static float tmp_data[VBUS_GRP_COUNT][32768];
	struct dev_context *devc = sdi->priv;
	struct sr_datafeed_packet packet[VBUS_GRP_COUNT];
	uint64_t tlen = devc->vbus_delta * 24 / 10000;
	uint64_t len = MIN(32768, tlen);
	unsigned i;
	int g;

	for (g = 0; g < devc->vbus_channels; g++) {
		float val = g == VBUS_V ? mv/1000.0 : ma/1000.0;
		packet[g].type = SR_DF_ANALOG;
		packet[g].payload = &devc->vbus_packet[g];
		devc->vbus_packet[g].data = tmp_data[g];
		for (i = 0; i < len; i++)
			tmp_data[g][i] = val;
	}

	do {
		for (g = 0; g < devc->vbus_channels; g++) {
			devc->vbus_packet[g].num_samples = len;
			sr_session_send(sdi, &packet[g]);
		}
		tlen -= len;
		len = MIN(32768, tlen);
	} while (tlen);
}

SR_PRIV void LIBUSB_CALL twinkie_vbus_sent(struct libusb_transfer *transfer)
{
	struct sr_dev_inst *sdi = transfer->user_data;
	struct dev_context *devc = sdi->priv;
	struct libusb_transfer *in_xfer = devc->transfers[11];
	struct timespec tsample;
	uint64_t now;

	/* acquisition has already ended */
	if (devc->sent_samples < 0 || transfer->status == LIBUSB_TRANSFER_NO_DEVICE)
		goto abort_vbus;

	if (transfer->status != LIBUSB_TRANSFER_COMPLETED)
		goto abort_vbus;

	clock_gettime(CLOCK_REALTIME, &tsample);
	now = tsample.tv_nsec + (uint64_t)tsample.tv_sec *1000000000ULL;
	devc->vbus_delta = now - devc->vbus_t0;
	devc->vbus_t0 = now;
	if (libusb_submit_transfer(in_xfer) != LIBUSB_SUCCESS)
		goto abort_vbus;

	return;
abort_vbus:
	libusb_free_transfer(transfer);
	libusb_free_transfer(in_xfer);
	devc->transfers[10] = NULL;
	devc->transfers[11] = NULL;
	devc->submitted_transfers--;
	if (devc->submitted_transfers == 0)
		finish_acquisition(sdi);
}

SR_PRIV void LIBUSB_CALL twinkie_vbus_recv(struct libusb_transfer *transfer)
{
	struct sr_dev_inst *sdi = transfer->user_data;
	struct dev_context *devc = sdi->priv;
	struct libusb_transfer *out_xfer = devc->transfers[10];

	/* acquisition has already ended */
	if (devc->sent_samples < 0 || transfer->status == LIBUSB_TRANSFER_NO_DEVICE)
		goto abort_vbus;

	if (transfer->status == LIBUSB_TRANSFER_COMPLETED &&
		transfer->actual_length) {
		int vbus_ma, vbus_mv;
		int len = transfer->actual_length;
		if (len > 63)
			len = 63;
		devc->vbus_data[len] = 0;
		if (sscanf(devc->vbus_data, VBUS_FORMAT, &vbus_mv, &vbus_ma) == 2) {
			export_vbus(sdi, vbus_mv, vbus_ma);
		}
	}

	if (libusb_submit_transfer(out_xfer) != LIBUSB_SUCCESS)
		goto abort_vbus;

	return;
abort_vbus:
	libusb_free_transfer(transfer);
	libusb_free_transfer(out_xfer);
	devc->transfers[10] = NULL;
	devc->transfers[11] = NULL;
	devc->submitted_transfers--;
	if (devc->submitted_transfers == 0)
		finish_acquisition(sdi);
}