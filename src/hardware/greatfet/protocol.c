/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2019 Katherine J. Temkin <k@ktemkin.com>
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

#include <config.h>

#include <libusb.h>
#include <errno.h>
#include <inttypes.h>

#include "protocol.h"

/**
 * Raw packet describing the output format for a libgreat command.
 */
struct libgreat_command_packet {
	uint32_t class_number;
	uint32_t verb_number;
	uint8_t payload[GREATFET_LOGIC_MAX_DATA_OUT];
	uint32_t payload_length;
} __attribute__((packed));

/**
 * Command block describing an acquisition; sent with the start command.
 */
struct libgreat_start_command_payload {
	uint32_t sample_rate_hz;
} __attribute__((packed));

/**
 * Command block for the payload sent with a configure command.
 */
struct libgreat_configure_command_payload {
	uint32_t sample_rate_hz;
	uint8_t num_channels;
} __attribute__((packed));

/**
 * Struct representing the response from a configure command.
 */
struct libgreat_configure_command_response {
	uint32_t sample_rate_achieved_hz;
	uint32_t buffer_size;
	uint8_t endpoint;
} __attribute__((packed));

/**
 * Executes a libgreat-style command.
 *
 * @param device The Sigrok GreatFET capture device that will execute the
 *     relevant GreatFET command.
 * @param command A packet describing the command to be executed.
 * @param response_buffer Buffer that will receive any response generated by
 *     the command, or NULL to receive no response.
 * @param response_max_length The maximum length of response to allow, or 0 to
 *     allow no response. Must be 0 if response_buffer is NULL.
 * @param timeout The timeout for the given command, in milliseconds. Matches
 *     a libusb timeout.
 */
static int greatfet_execute_libgreat_command(
	const struct sr_dev_inst *device,
	struct libgreat_command_packet *command, void *response_buffer,
	size_t response_max_length, unsigned int timeout)
{
	struct sr_usb_dev_inst *connection = device->conn;
	int rc;

	// Communications flags, which specify e.g. optimizations in our normal
	// communications.
	uint16_t flags = 0;

	// The command length is the payload length, plus the length of the headers.
	uint16_t command_length =
		command->payload_length + (2 * sizeof(uint32_t));

	// If we're not expecting any data back, we won't bother trying to read any.
	// Notify the device not to expect us to.
	if (response_max_length == 0) {
		flags |= GREATFET_LIBGREAT_FLAG_SKIP_RESPONSE;
	}

	// Send the command to the device...
	rc = libusb_control_transfer(
		connection->devhdl,
		LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR |
			LIBUSB_RECIPIENT_ENDPOINT,
		GREATFET_LIBGREAT_REQUEST_NUMBER,
		GREATFET_LIBGREAT_VALUE_EXECUTE, flags,
		(unsigned char *)command, command_length, timeout);
	if (rc < 0) {
		// If we're not a "please retry", print the error message.
		if (rc != LIBUSB_ERROR_BUSY) {
			sr_err("command submission failed: libusb error %s (%d)\n",
			       libusb_error_name(rc), rc);
		}

		return rc;
	}

	// If we're not expecting a response from the device, we're done!
	// Indicate we succesfully received zero bytes of response.
	if (response_max_length == 0) {
		return 0;
	}

	// Read the response back from the device, and return either its length
	// or an error code.
	rc = libusb_control_transfer(
		connection->devhdl,
		LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_VENDOR |
			LIBUSB_RECIPIENT_ENDPOINT,
		GREATFET_LIBGREAT_REQUEST_NUMBER,
		GREATFET_LIBGREAT_VALUE_EXECUTE, 0,
		(unsigned char *)response_buffer, response_max_length, timeout);

	return rc;
}

/**
 * @returns a string containing the core string, or NULL if one can't be read.
 *    Should be freed with g_free when complete.
 */
static char *greatfet_read_core_string(struct sr_dev_inst *device,
				       uint32_t verb_number)
{
	int len;

	char value[GREATFET_LOGIC_MAX_STRING_LENGTH + 1];
	struct libgreat_command_packet packet = { .class_number =
							  GREATFET_CLASS_CORE,
						  .verb_number = verb_number,
						  .payload_length = 0 };

	len = greatfet_execute_libgreat_command(
		device, &packet, value, GREATFET_LOGIC_MAX_STRING_LENGTH,
		GREATFET_LOGIC_DEFAULT_TIMEOUT);

	if (len < 0) {
		return NULL;
	}

	// Null terminate the string, and then copy it.
	value[len] = 0;
	return g_strdup(value);
}

/**
 * @returns a string containing the analyzer version, or NULL if one can't be read.
 *    Should be freed with g_free when complete.
 */
char *greatfet_get_version_number(struct sr_dev_inst *device)
{
	char *version = greatfet_read_core_string(
		device, GREATFET_CORE_VERB_READ_VERSION);
	return version;
}

/**
 * @returns a string containing the analyzer version, or NULL if one can't be read.
 *    Should be freed with g_free when complete.
*/
char *greatfet_get_serial_number(struct sr_dev_inst *device)
{
	return greatfet_read_core_string(device,
					 GREATFET_CORE_VERB_READ_SERIAL);
}

/**
 * Allocate the transfers we'll use to communicate with the GreatFET logic
 * analyzer.
 */
int greatfet_allocate_transfers(const struct sr_dev_inst *device)
{
	struct greatfet_context *context = device->priv;
	unsigned i;

	for (i = 0; i < GREATFET_TRANSFER_POOL_SIZE; i++) {
		context->transfers[i] = libusb_alloc_transfer(0);
		if (!context->transfers[i]) {
			return ENOMEM;
		}
	}

	return 0;
}

/**
 * Prepare the USB transfer objects for an acquisition.
 */
int greatfet_prepare_transfers(const struct sr_dev_inst *device,
			       libusb_transfer_cb_fn callback)
{
	unsigned i;
	int rc;

	struct greatfet_context *context = device->priv;
	struct sr_usb_dev_inst *connection = device->conn;

	context->active_transfer_count = 0;

	for (i = 0; i < GREATFET_TRANSFER_POOL_SIZE; i++) {
		libusb_fill_bulk_transfer(
			context->transfers[i], connection->devhdl,
			context->endpoint,
			&context->buffer[i * GREATFET_TRANSFER_BUFFER_SIZE],
			GREATFET_TRANSFER_BUFFER_SIZE, callback, (void *)device,
			0);

		if (context->transfers[i]->buffer == NULL) {
			return ENOMEM;
		}

		rc = libusb_submit_transfer(context->transfers[i]);
		context->active_transfer_count++;

		if (rc) {
			sr_spew("%s(): submitting bulk transfer failed: %s (%d)\n",
				__func__, libusb_error_name(rc), rc);
			return EIO;
		}
	}

	return 0;
}

/**
 * Cancel all outstanding transfers for a device -- usually called before we
 * abort a capture.
 */
int greatfet_cancel_transfers(struct sr_dev_inst *device)
{
	int rc = 0;
	struct greatfet_context *context = device->priv;
	unsigned i;

	for (i = 0; i < GREATFET_TRANSFER_POOL_SIZE; i++) {
		if (context->transfers[i]) {
			// A canceled transfer will cause will cause acquisition to be aborted
			// in the callback.
			rc = libusb_cancel_transfer(context->transfers[i]);
		}
	}
	return rc;
}

/**
 * Free a transfer and decrement the active transfer count,
 * and end the acquisition if there are no further active transitions.
 */
void greatfet_free_transfer(struct sr_dev_inst *device,
			    struct libusb_transfer *transfer)
{
	struct greatfet_context *greatfet_context = device->priv;
	struct drv_context *driver_context = device->driver->context;

	for (int i = 0; i < GREATFET_TRANSFER_POOL_SIZE; i++) {
		if (transfer == greatfet_context->transfers[i]) {
			greatfet_context->transfers[i] = NULL;
		}
	}

	libusb_free_transfer(transfer);
	greatfet_context->active_transfer_count--;

	// If that was the last transfer, then fully end the acquisition.
	if (greatfet_context->active_transfer_count == 0) {
		std_session_send_df_end(device);
		usb_source_remove(device->session, driver_context->sr_ctx);
	}
}

/**
 * Cancel and begin freeing transfers to end the acquisition.
 */
void greatfet_abort_acquisition(struct sr_dev_inst *device)
{
	struct greatfet_context *context = device->priv;

	context->acquisition_active = FALSE;
	greatfet_cancel_transfers(device);
}

/**
 * Ask the GreatFET device to configure itself.
 */
int greatfet_configure(const struct sr_dev_inst *device)
{
	struct greatfet_context *context = device->priv;
	struct sr_usb_dev_inst *connection = device->conn;
	int rc;

	uint8_t response_buffer[sizeof(
		struct libgreat_configure_command_response)];

	struct libgreat_configure_command_payload payload = {
		.sample_rate_hz = (uint32_t)context->sample_rate,
		.num_channels = (uint8_t)context->num_channels,
	};

	sr_dbg("%s(): configuring for %d channels\n", __func__,
	       context->num_channels);

	struct libgreat_command_packet packet = {
		.class_number = GREATFET_CLASS_LA,
		.verb_number = GREATFET_LA_VERB_CONFIGURE,
		.payload_length = sizeof(payload)
	};

	memcpy(packet.payload, &payload, sizeof(payload));

	rc = greatfet_execute_libgreat_command(device, &packet, response_buffer,
					       sizeof(response_buffer),
					       GREATFET_LOGIC_DEFAULT_TIMEOUT);

	struct libgreat_configure_command_response response;
	memcpy(&response, response_buffer,
	       sizeof(struct libgreat_configure_command_response));

	context->endpoint = response.endpoint;

	libusb_claim_interface(connection->devhdl, 1);

	return rc;
}

/**
 * Ask the GreatFET device to start logic aquisition.
 */
int greatfet_start_acquire(const struct sr_dev_inst *device)
{
	int rc;

	rc = greatfet_configure(device);
	if (rc < 0) {
		return SR_ERR_IO;
	}

	struct libgreat_command_packet packet = {
		.class_number = GREATFET_CLASS_LA,
		.verb_number = GREATFET_LA_VERB_START,
		.payload_length = 0
	};

	sr_info("%s(): starting acquisition\n", __func__);
	rc = greatfet_execute_libgreat_command(device, &packet, NULL, 0,
					       GREATFET_LOGIC_DEFAULT_TIMEOUT);

	sr_dbg("%s(): greatfet_execute_libgreat_command returned %s (%d)\n",
	       __func__, libusb_error_name(rc), rc);

	return (rc < 0) ? SR_ERR_IO : SR_OK;
}

/**
 * Ask the GreatFET device to halt logic aquisition.
 */
int greatfet_stop_acquire(const struct sr_dev_inst *device)
{
	struct sr_usb_dev_inst *connection = device->conn;
	int rc;

	sr_spew("Halting logic aquisition...\n");

	rc = libusb_release_interface(connection->devhdl, 1);
	sr_spew("release_interface: %d\n", rc);

	struct libgreat_command_packet packet = {
		.class_number = GREATFET_CLASS_LA,
		.verb_number = GREATFET_LA_VERB_STOP,
		.payload_length = 0,
	};

	sr_info("%s(): stopping acquisition\n", __func__);
	rc = greatfet_execute_libgreat_command(device, &packet, NULL, 0,
					       GREATFET_LOGIC_DEFAULT_TIMEOUT *
						       1000);

	return rc;
}
