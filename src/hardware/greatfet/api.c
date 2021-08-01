/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2019 Katherine J. Temkin <k@ktemkin.com>
 *
 * This program is free software; you can redistribute it and/or modify
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <libsigrok/libsigrok.h>

#include <config.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libsigrok-internal.h"
#include "protocol.h"

#define NUM_LOGIC_CHANNELS (8)
#define DEFAULT_SAMPLE_RATE SR_MHZ(34)

static const uint32_t scanopts[] = {
	SR_CONF_CONN,
};

static const uint32_t driver_options[] = {
	SR_CONF_LOGIC_ANALYZER,
};

static const uint64_t samplerates[] = {
	SR_KHZ(40800), SR_MHZ(34), SR_KHZ(25500), SR_KHZ(20040), SR_MHZ(17),
};

static const char *channel_names[] = {
	"SGPIO0", "SGPIO1", "SGPIO2", "SGPIO3",
	"SGPIO4", "SGPIO5", "SGPIO6", "SGPIO7",
};

static const uint32_t device_options[] = {
	SR_CONF_CONTINUOUS,
	SR_CONF_LIMIT_SAMPLES | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_SAMPLERATE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_TRIGGER_MATCH | SR_CONF_LIST,
	// TODO: use CAPTURE_RATIO
	SR_CONF_CAPTURE_RATIO | SR_CONF_GET | SR_CONF_SET,
};

static const int32_t trigger_matches[] = {
	SR_TRIGGER_ZERO,    SR_TRIGGER_ONE,  SR_TRIGGER_RISING,
	SR_TRIGGER_FALLING, SR_TRIGGER_EDGE,
};

static GSList *scan(struct sr_dev_driver *driver, GSList *options)
{
	unsigned i;

	struct drv_context *driver_context = driver->context;

	GSList *connected_devices, *devices, *usb_device;
	struct sr_dev_inst *device;
	struct greatfet_context *context;
	struct sr_usb_dev_inst *connection;

	connected_devices = sr_usb_find(driver_context->sr_ctx->libusb_ctx,
					GREATFET_VID_PID);

	if (!connected_devices)
		return NULL;

	// TODO: support parsing e.g. libgreat connection URI to be able to select
	// a device e.g. by serial from SR_CONF_CONN

	// Iterate over all devices that match the GreatFET VID/PID, get their
	// information, and filter out ones that don't support logic analyzer modes.
	devices = NULL;
	for (usb_device = connected_devices; usb_device;
	     usb_device = usb_device->next) {
		connection = usb_device->data;

		sr_spew("Allocating memory for sigrok device and device context");
		context = g_malloc0(sizeof(struct greatfet_context));
		device = g_malloc0(sizeof(struct sr_dev_inst));
		device->priv = context;

		device->conn = usb_device->data;
		device->inst_type = SR_INST_USB;
		device->status = SR_ST_INACTIVE;

		sr_spew("Opening GreatFET USB Device temporarily to fetch properties.\n");
		if (sr_usb_open(driver_context->sr_ctx->libusb_ctx,
				connection) != SR_OK) {
			continue;
		}

		device->vendor = g_strdup("Great Scott Gadgets");
		device->model = g_strdup("GreatFET");

		sr_spew("Getting device version and serial number...\n");
		device->version = greatfet_get_version_number(device);
		if (!device->version) {
			device->version = g_strdup("(unknown version)");
		}
		device->serial_num = greatfet_get_serial_number(device);
		if (device->serial_num) {
			device->connection_id = g_strdup(device->serial_num);
		} else {
			device->serial_num = g_strdup("(unknown serial)");
		}

		sr_spew("Initializing device context...\n");
		context->num_channels = ARRAY_SIZE(channel_names);
		context->sample_rate = DEFAULT_SAMPLE_RATE;

		sr_spew("Setting up device channels...\n");
		for (i = 0; i < context->num_channels; ++i) {
			const char *name = channel_names[i];
			sr_channel_new(device, i, SR_CHANNEL_LOGIC, TRUE, name);
		}

		devices = g_slist_append(devices, device);

		sr_spew("Closing GreatFET USB Device.\n");
		sr_usb_close(connection);
		sr_spew("Device closed.\n");
	}

	g_slist_free(connected_devices);

	return std_scan_complete(driver, devices);
}

static int dev_open(struct sr_dev_inst *device)
{
	struct sr_dev_driver *driver = device->driver;
	struct drv_context *driver_context = driver->context;
	struct sr_usb_dev_inst *connection = device->conn;

	if (sr_usb_open(driver_context->sr_ctx->libusb_ctx, connection) !=
	    SR_OK) {
		return SR_ERR;
	}

	return SR_OK;
}

static int dev_close(struct sr_dev_inst *device)
{
	struct sr_usb_dev_inst *connection = device->conn;

	if (!connection->devhdl)
		return SR_ERR_BUG;

	libusb_release_interface(connection->devhdl, GREATFET_USB_INTERFACE);
	libusb_close(connection->devhdl);

	connection->devhdl = NULL;
	return SR_OK;
}

static int dev_clear(const struct sr_dev_driver *device)
{
	return std_dev_clear(device);
}

static int config_get(uint32_t key, GVariant **data,
		      const struct sr_dev_inst *device,
		      const struct sr_channel_group *cg)
{
	struct greatfet_context *context = device->priv;
	(void)cg;

	switch (key) {
	case SR_CONF_SAMPLERATE:
		*data = g_variant_new_uint64(context->sample_rate);
		return SR_OK;
	case SR_CONF_LIMIT_SAMPLES:
		*data = g_variant_new_uint64(context->capture_limit_samples);
		return SR_OK;
	case SR_CONF_CAPTURE_RATIO:
		*data = g_variant_new_uint64(context->capture_ratio);
		return SR_OK;
	}

	return SR_ERR_NA;
}

static int config_set(uint32_t key, GVariant *data,
		      const struct sr_dev_inst *device,
		      const struct sr_channel_group *cg)
{
	struct greatfet_context *context = device->priv;
	(void)cg;

	switch (key) {
	case SR_CONF_SAMPLERATE:
		context->sample_rate = g_variant_get_uint64(data);
		return SR_OK;
	case SR_CONF_LIMIT_SAMPLES:
		context->capture_limit_samples = g_variant_get_uint64(data);
		return SR_OK;
	case SR_CONF_CAPTURE_RATIO:
		context->capture_ratio = g_variant_get_uint64(data);
		return SR_OK;
	}

	return SR_ERR_NA;
}

static int config_list(uint32_t key, GVariant **data,
		       const struct sr_dev_inst *device,
		       const struct sr_channel_group *channel_group)
{
	switch (key) {
	case SR_CONF_SCAN_OPTIONS:
	case SR_CONF_DEVICE_OPTIONS:
		return STD_CONFIG_LIST(key, data, device, channel_group,
				       scanopts, driver_options,
				       device_options);
	case SR_CONF_SAMPLERATE:
		*data = std_gvar_samplerates(ARRAY_AND_SIZE(samplerates));
		break;
	case SR_CONF_TRIGGER_MATCH:
		*data = std_gvar_array_i32(ARRAY_AND_SIZE(trigger_matches));
		break;
	default:
		return SR_ERR_NA;
	}

	return SR_OK;
}

static void handle_transferred_samples(struct sr_dev_inst *device,
				       uint8_t *data, size_t length)
{
	struct greatfet_context *context = device->priv;
	int trigger_offset;
	uint32_t num_samples = length;
	int pre_trigger_samples;

	struct sr_datafeed_logic logic = { .length = length,
					   .unitsize = 1,
					   .data = data };

	struct sr_datafeed_packet packet = { .type = SR_DF_LOGIC,
					     .payload = &logic };

	if (!context->trigger_fired) {
		trigger_offset = soft_trigger_logic_check(
			context->stl, data, length, &pre_trigger_samples);

		if (trigger_offset > -1) {
			context->samples_captured += pre_trigger_samples;
			logic.length = length - trigger_offset;
			logic.data = data + trigger_offset;
			context->trigger_fired = TRUE;
		}
	}

	if (context->trigger_fired) {
		sr_session_send(device, &packet);
		context->samples_captured += num_samples;
	}
}

static gboolean transfer_should_stop(struct sr_dev_inst *device)
{
	struct greatfet_context *context = device->priv;

	if (!context->capture_limit_samples) {
		return FALSE;
	}

	if (context->samples_captured < context->capture_limit_samples) {
		return FALSE;
	}

	sr_dbg("Met sample goal with %" PRIu64 "  samples (trying for %" PRIu64
	       ")\n",
	       context->samples_captured, context->capture_limit_samples);
	return TRUE;
}

static void LIBUSB_CALL
sample_transfer_complete(struct libusb_transfer *transfer)
{
	int rc;

	struct sr_dev_inst *device = transfer->user_data;
	struct greatfet_context *context = device->priv;

	if (!context->acquisition_active) {
		greatfet_free_transfer(device, transfer);
		return;
	}

	sr_dbg("%s(): status %s; received %d bytes.", __func__,
	       libusb_error_name(transfer->status), transfer->actual_length);

	switch (transfer->status) {
	case LIBUSB_TRANSFER_TIMED_OUT:
		// If the transfer timed out, we may have gotten some data, but not all of
		// the data we wanted. Process the data we have, but emit a warning.
		sr_warn("%s(): transfer timed out; trying to use what data we received\n",
			__func__);
		/* fall through */
	case LIBUSB_TRANSFER_COMPLETED:
		handle_transferred_samples(device, transfer->buffer,
					   transfer->actual_length);
		break;
	case LIBUSB_TRANSFER_CANCELLED:
		greatfet_free_transfer(device, transfer);
		greatfet_abort_acquisition(device);
		return;
	default:
		sr_err("%s(): transfer failed (%s), bailing out\n", __func__,
		       libusb_error_name(transfer->status));
		greatfet_free_transfer(device, transfer);
		greatfet_abort_acquisition(device);
		return;
	}

	if (transfer_should_stop(device)) {
		greatfet_free_transfer(device, transfer);
		greatfet_abort_acquisition(device);
		return;
	}

	rc = libusb_submit_transfer(transfer);
	if (rc < 0) {
		// Re-submit the transfer, so our buffer can be used for future sampling
		sr_err("%s(): resubmitting transfer failed (%s), bailing out\n",
		       __func__, libusb_error_name(rc));
		greatfet_free_transfer(device, transfer);
		greatfet_abort_acquisition(device);
		return;
	}
}

static int receive_data(int fd, int revents, void *cb_data)
{
	struct timeval tv;
	struct drv_context *driver_context = (struct drv_context *)cb_data;

	tv.tv_sec = tv.tv_usec = 0;
	libusb_handle_events_timeout(driver_context->sr_ctx->libusb_ctx, &tv);

	return TRUE;
}

static int dev_acquisition_start(const struct sr_dev_inst *device)
{
	int rc;
	struct greatfet_context *context = device->priv;
	struct drv_context *driver_context = device->driver->context;
	struct sr_trigger *trigger;

	if ((trigger = sr_session_trigger_get(device->session))) {
		int pre_trigger_samples = 0;
		if (context->capture_limit_samples > 0)
			pre_trigger_samples = (context->capture_ratio *
					       context->capture_limit_samples) /
					      100;
		context->stl = soft_trigger_logic_new(device, trigger,
						      pre_trigger_samples);
		if (!context->stl)
			return SR_ERR_MALLOC;
		context->trigger_fired = FALSE;
	} else
		context->trigger_fired = TRUE;

	context->acquisition_active = TRUE;
	context->samples_captured = 0;

	// Let the Sigrok core know we're going to be providing data via USB.
	// This allows it to periodically call libusb's event handler.
	usb_source_add(device->session, driver_context->sr_ctx,
		       GREATFET_LOGIC_DEFAULT_TIMEOUT, receive_data,
		       driver_context);
	std_session_send_df_header(device);

	greatfet_allocate_transfers(device);

	rc = greatfet_start_acquire(device);

	greatfet_prepare_transfers(device, sample_transfer_complete);

	return rc;
}

static int dev_acquisition_stop(struct sr_dev_inst *device)
{
	struct greatfet_context *context = device->priv;
	int rc;
	greatfet_abort_acquisition(device);
	rc = greatfet_stop_acquire(device);
	if (context->stl) {
		soft_trigger_logic_free(context->stl);
		context->stl = NULL;
	}
	return rc;
}

static struct sr_dev_driver greatfet_driver_info = {
	.name = "greatfet",
	.longname = "GreatFET",
	.api_version = 1,

	.init = std_init,
	.cleanup = std_cleanup,

	.scan = scan,

	.dev_list = std_dev_list,
	.dev_clear = dev_clear,

	.config_get = config_get,
	.config_set = config_set,
	.config_list = config_list,

	.dev_open = dev_open,
	.dev_close = dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = dev_acquisition_stop,

	.context = NULL,
};
SR_REGISTER_DEV_DRIVER(greatfet_driver_info);
