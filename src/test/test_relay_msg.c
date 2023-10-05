/* Copyright (c) 2023, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_relay_msg.c
 * \brief Test the relay message subsystem.
 **/

#include "core/or/or.h"

#include "app/config/config.h"

#include "core/or/cell_st.h"
#include "core/or/relay.h"
#include "core/or/relay_cell.h"
#include "core/or/relay_msg.h"

#include "lib/log/util_bug.h"

/* Test suite stuff */
#include "test/test.h"
#include "test/log_test_helpers.h"

/** Static buffer used as a placeholder to build cells. */
static uint8_t g_buf[493] = {0};

/* Helper macro to build a relay message using the "msg" stack allocate
 * variable. */
#define MAKE_RELAY_MSG(id, cmd, body_s)                   \
  do {                                                    \
    relay_msg_clear(&msg);                                \
    relay_msg_set(0, cmd, id, (const uint8_t *) (body_s), \
                  sizeof((body_s)) - 1, &msg);            \
  } while (0)

/* Helper macro to build a cell. */
#define MAKE_RELAY_CELL_V0(c, cmd, s_id, b, b_len)  \
  do {                                              \
    memset(c, 0, sizeof(cell_t));                   \
    c->circ_id = 23;                                \
    c->command = CELL_RELAY;                        \
    c->relay_cell_proto = 0;                        \
    build_relay_cell_hdr_v0(cmd, s_id, b_len, c); \
    relay_cell_set_payload(c, (const uint8_t *)b, b_len);            \
  } while (0)

/* Helper macro to build a cell. */
#define MAKE_RELAY_CELL_V1(c, cmd, s_id, b, b_len)          \
  do {                                                      \
    size_t __offset = 0;                                    \
    memset(c, 0, sizeof(cell_t));                           \
    memset(&g_buf, 0, sizeof(g_buf));                       \
    c->circ_id = 23;                                        \
    c->command = CELL_RELAY;                                \
    c->relay_cell_proto = 1;                                \
    build_relay_cell_hdr_v1(c);                             \
    __offset += build_message_hdr(cmd, s_id, b_len, g_buf); \
    memcpy(g_buf + __offset, b, b_len);                     \
    __offset += b_len;                                      \
    set_uint8(g_buf + __offset, 0);                         \
    __offset += 1;                                          \
    relay_cell_set_payload(c, g_buf, __offset);             \
  } while (0)

/** Helper: Set a relay cell header v0 into the giving buf and return the
 * offset in the buffer we have written up to. */
static size_t
build_relay_cell_hdr_v0(uint8_t cmd, streamid_t stream_id, uint16_t length,
                        cell_t *cell)
{
  relay_header_t rh;

  memset(&rh, 0, sizeof(rh));
  rh.command = cmd;
  rh.stream_id = stream_id;
  rh.length = length;
  rh.recognized = 0;
  /* Leave the integrity to 0. For v0, that field is set in this relay header
   * but after encoding during encryption stage. */
  relay_header_pack(cell->payload, &rh);

  return sizeof(rh);
}

/** Helper: Set a relay cell header v1 into the giving buf and return the
 * offset in the buffer we have written up to. */
static size_t
build_relay_cell_hdr_v1(cell_t *cell)
{
  uint8_t digest[14] = {0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                        0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x4a, 0x4b};
  size_t offset = 0;

  /* Recognized field. */
  set_uint16(cell->payload, 0);
  offset += sizeof(uint16_t);
  /* Digest field. */
  relay_cell_set_digest(cell, digest);
  offset += sizeof(digest);

  return offset;
}

/** Helper: With the given values, build a relay message header into the buffer
 * and return the offset in that buffer we have written up to. */
static size_t
build_message_hdr(uint8_t cmd, streamid_t stream_id, uint16_t length,
                  uint8_t *buf_out)
{
  size_t offset = 0;

  set_uint8(buf_out, cmd);
  offset += sizeof(cmd);
  set_uint16(buf_out + offset, htons(length));
  offset += sizeof(length);
  if (stream_id != 0) {
    set_uint16(buf_out + offset, htons(stream_id));
    offset += sizeof(stream_id);
  }

  return offset;
}

static void
test_decoder_invalid_v1(void *arg)
{
  cell_t cell;
  relay_msg_t *msg = NULL;

  (void) arg;

  setup_full_capture_of_logs(LOG_PROTOCOL_WARN);

  relay_msg_decoder_t decoder;
  relay_msg_decoder_init(&decoder, 1);
  tt_int_op(decoder.relay_cell_proto, OP_EQ, 1);

  const char *body = "\x01\x02\x03\x04\x05\x06\x07\x08";
  MAKE_RELAY_CELL_V1((&cell), RELAY_COMMAND_DATA, 42, body,
                     strlen(body));

  /* End of message market at the start. */
  set_uint8(cell.payload + relay_cell_get_header_size(1) , 0);

  relay_msg_decoder_add_cell(&cell, &decoder);
  expect_log_msg_containing("End-of-message marker at the start. "
                            "Invalid v1 cell.");

  /* Unknown relay command. */
  MAKE_RELAY_CELL_V1((&cell), 246, 42, body, strlen(body));
  set_uint16(cell.payload + relay_cell_get_header_size(1) +
             sizeof(uint8_t), htons(600));
  relay_msg_decoder_add_cell(&cell, &decoder);
  expect_log_msg_containing("Unknown relay command 246. Invalid v1 cell.");

  /* Too big length. */
  MAKE_RELAY_CELL_V1((&cell), RELAY_COMMAND_DATA, 42, body,
                     strlen(body));
  set_uint16(cell.payload + relay_cell_get_header_size(1) +
             sizeof(uint8_t), htons(600));
  relay_msg_decoder_add_cell(&cell, &decoder);
  expect_log_msg_containing("Relay message body length is too big: "
                            "600 vs 488. Invalid v1 cell.");

 done:
  relay_msg_free(msg);
  relay_msg_decoder_clear(&decoder);
  teardown_capture_of_logs();
}

static void
test_decoder_valid_v0(void *arg)
{
  cell_t cell_custom, *cell_data;
  relay_msg_t *msg_custom = NULL, *msg_data = NULL;
  smartlist_t *messages = NULL;
  relay_msg_codec_t codec;

  (void) arg;

  relay_msg_codec_init(&codec, 0);
  tt_int_op(codec.relay_cell_proto, OP_EQ, 0);

  relay_msg_decoder_t *decoder = &codec.decoder;
  relay_msg_encoder_t *encoder = &codec.encoder;

  const char *body = "\x01\x02\x03\x04\x05\x06\x07\x08";
  MAKE_RELAY_CELL_V0((&cell_custom), RELAY_COMMAND_DATA, 42, body,
                     strlen(body));

  relay_msg_decoder_add_cell(&cell_custom, decoder);
  /* Shouldn't be pending, should be ready. */
  tt_assert(!decoder->pending);
  tt_int_op(decoder->pending_len, OP_EQ, 0);
  tt_int_op(smartlist_len(decoder->ready), OP_EQ, 1);

  /* Take the message as in its ownership. */
  messages = relay_msg_decoder_take(decoder);
  tt_int_op(smartlist_len(decoder->ready), OP_EQ, 0); // Empty ready list.
  tt_assert(messages);
  tt_int_op(smartlist_len(messages), OP_EQ, 1);
  msg_custom = smartlist_pop_last(messages);

  /* Check if it matches our initial cell. */
  tt_int_op(msg_custom->relay_cell_proto, OP_EQ, 0);
  tt_int_op(msg_custom->command, OP_EQ, RELAY_COMMAND_DATA);
  tt_int_op(msg_custom->length, OP_EQ, 8);
  tt_int_op(msg_custom->stream_id, OP_EQ, 42);
  tt_mem_op(msg_custom->body, OP_EQ, body, msg_custom->length);

  /*
   * Now, we'll encode a cell with our encoding subsystem and compare it with
   * the one we built from scratch above.
   */

  bool ret = relay_msg_encoder_add_msg(&codec, msg_custom);
  tt_assert(ret);
  tt_int_op(smartlist_len(encoder->ready_cells), OP_EQ, 1);
  cell_data = smartlist_get(encoder->ready_cells, 0);
  /* Header is 11 + 8 (data) + 4 (zero bytes from the random padding) = 23 */
  tt_mem_op(&cell_custom.payload, OP_EQ, &cell_data->payload, 23);

  /* Pass this cell back into our decoder and make sure the resulting message
   * is matching the first message we got from our custom cell. */
  relay_msg_decoder_add_cell(cell_data, decoder);
  tt_assert(!decoder->pending);
  tt_int_op(decoder->pending_len, OP_EQ, 0);
  tt_int_op(smartlist_len(decoder->ready), OP_EQ, 1);

  smartlist_free(messages);
  messages = relay_msg_decoder_take(decoder);
  tt_assert(messages);
  msg_data = smartlist_pop_last(messages);
  tt_assert(msg_data);
  /* Validate with our custom message. */
  tt_int_op(msg_custom->command, OP_EQ, msg_data->command);
  tt_int_op(msg_custom->length, OP_EQ, msg_data->length);
  tt_int_op(msg_custom->relay_cell_proto, OP_EQ, msg_data->relay_cell_proto);
  tt_int_op(msg_custom->stream_id, OP_EQ, msg_data->stream_id);
  tt_mem_op(msg_custom->body, OP_EQ, msg_data->body, msg_custom->length);

 done:
  smartlist_free(messages);
  relay_msg_free(msg_custom);
  relay_msg_free(msg_data);
  relay_msg_codec_clear(&codec);
}

static void
test_decoder_valid_v1(void *arg)
{
  cell_t cell_custom, *cell_data;
  relay_msg_t *msg_custom = NULL, *msg_data = NULL;
  smartlist_t *messages = NULL;
  relay_msg_codec_t codec;

  (void) arg;

  relay_msg_codec_init(&codec, 1);
  tt_int_op(codec.relay_cell_proto, OP_EQ, 1);

  relay_msg_decoder_t *decoder = &codec.decoder;
  relay_msg_encoder_t *encoder = &codec.encoder;

  const char *body = "\x01\x02\x03\x04\x05\x06\x07\x08";
  MAKE_RELAY_CELL_V1((&cell_custom), RELAY_COMMAND_DATA, 42, body,
                     strlen(body));

  relay_msg_decoder_add_cell(&cell_custom, decoder);
  /* Shouldn't be pending, should be ready. */
  tt_assert(!decoder->pending);
  tt_int_op(decoder->pending_len, OP_EQ, 0);
  tt_int_op(smartlist_len(decoder->ready), OP_EQ, 1);

  /* Take the message as in its ownership. */
  messages = relay_msg_decoder_take(decoder);
  tt_int_op(smartlist_len(decoder->ready), OP_EQ, 0); // Empty ready list.
  tt_assert(messages);
  tt_int_op(smartlist_len(messages), OP_EQ, 1);
  msg_custom = smartlist_pop_last(messages);

  /* Check if it matches our initial cell. */
  tt_int_op(msg_custom->relay_cell_proto, OP_EQ, 1);
  tt_int_op(msg_custom->command, OP_EQ, RELAY_COMMAND_DATA);
  tt_int_op(msg_custom->length, OP_EQ, 8);
  tt_int_op(msg_custom->stream_id, OP_EQ, 42);
  tt_mem_op(msg_custom->body, OP_EQ, body, msg_custom->length);

  /*
   * Now, we'll encode a cell with our encoding subsystem and compare it with
   * the one we built from scratch above.
   */

  bool ret = relay_msg_encoder_add_msg(&codec, msg_custom);
  tt_assert(ret);
  tt_int_op(smartlist_len(encoder->ready_cells), OP_EQ, 1);
  cell_data = smartlist_get(encoder->ready_cells, 0);
  /* Skip the relay cell header with the digest and recognized field. Only
   * compare the payload: 5 (msg hdr) + 8 (data) + 1 (end-of-message marker) +
   * 4 (zero bytes from the random padding) = 18 */
  tt_mem_op(cell_custom.payload + 16, OP_EQ, cell_data->payload + 16, 18);

  /* Pass this cell back into our decoder and make sure the resulting message
   * is matching the first message we got from our custom cell. */
  relay_msg_decoder_add_cell(cell_data, decoder);
  tt_assert(!decoder->pending);
  tt_int_op(decoder->pending_len, OP_EQ, 0);
  tt_int_op(smartlist_len(decoder->ready), OP_EQ, 1);

  smartlist_free(messages);
  messages = relay_msg_decoder_take(decoder);
  tt_assert(messages);
  msg_data = smartlist_pop_last(messages);
  tt_assert(msg_data);
  /* Validate with our custom message. */
  tt_int_op(msg_custom->command, OP_EQ, msg_data->command);
  tt_int_op(msg_custom->length, OP_EQ, msg_data->length);
  tt_int_op(msg_custom->relay_cell_proto, OP_EQ, msg_data->relay_cell_proto);
  tt_int_op(msg_custom->stream_id, OP_EQ, msg_data->stream_id);
  tt_mem_op(msg_custom->body, OP_EQ, msg_data->body, msg_custom->length);

 done:
  smartlist_free(messages);
  relay_msg_free(msg_custom);
  relay_msg_free(msg_data);
  relay_msg_codec_clear(&codec);
}

static void
test_encoder_valid_v0(void *arg)
{
  cell_t *cell;
  relay_msg_t msg;
  uint8_t payload[4] = { 'A', 'b', 'C', 'd' };
  relay_msg_codec_t codec;

  (void) arg;

  relay_msg_codec_init(&codec, 0);

  relay_msg_set(0, RELAY_COMMAND_DATA, 42, payload, sizeof(payload), &msg);
  tt_int_op(msg.relay_cell_proto, OP_EQ, 0);
  tt_int_op(msg.length, OP_EQ, sizeof(payload));
  tt_int_op(msg.command, OP_EQ, RELAY_COMMAND_DATA);
  tt_int_op(msg.stream_id, OP_EQ, 42);
  tt_mem_op(msg.body, OP_EQ, payload, msg.length);

  const uint8_t EXPECTED_CELL_PAYLOAD[] =
    "\x02"              // command
    "\x00\x00"          // recognized
    "\x00\x2A"          // stream id
    "\x00\x00\x00\x00"  // digest
    "\x00\x04"          // length
    "\x41\x62\x43\x64"  // payload
    "\x00\x00\x00\x00"; // zero pading.

  bool ret = relay_msg_encoder_add_msg(&codec, &msg);
  tt_assert(ret);

  tt_int_op(smartlist_len(codec.encoder.ready_cells), OP_EQ, 1);
  cell = smartlist_get(codec.encoder.ready_cells, 0);
  tt_mem_op(cell->payload, OP_EQ, EXPECTED_CELL_PAYLOAD,
            sizeof(EXPECTED_CELL_PAYLOAD) - 1);

 done:
  relay_msg_codec_clear(&codec);
  relay_msg_clear(&msg);
}

static void
test_encoder_valid_v1(void *arg)
{
  const cell_t *cell = NULL;
  relay_msg_t msg;
  uint8_t payload[4] = { 'A', 'b', 'C', 'd' };
  relay_msg_codec_t codec;

  (void) arg;

  relay_msg_codec_init(&codec, 1);

  relay_msg_set(1, RELAY_COMMAND_DATA, 42, payload, sizeof(payload), &msg);
  tt_int_op(msg.relay_cell_proto, OP_EQ, 1);
  tt_int_op(msg.length, OP_EQ, sizeof(payload));
  tt_int_op(msg.command, OP_EQ, RELAY_COMMAND_DATA);
  tt_int_op(msg.stream_id, OP_EQ, 42);
  tt_mem_op(msg.body, OP_EQ, payload, msg.length);

  const uint8_t EXPECTED_CELL_PAYLOAD[] =
    "\x00\x00"          // recognized
    "\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00" // digest
    "\x02"              // command
    "\x00\x04"          // length
    "\x00\x2A"          // (optional) stream id
    "\x41\x62\x43\x64"  // payload
    "\x00"              // End of Message marker.
    "\x00\x00\x00\x00"; // zero pading.

  bool ret = relay_msg_encoder_add_msg(&codec, &msg);
  tt_assert(ret);

  tt_int_op(smartlist_len(codec.encoder.ready_cells), OP_EQ, 1);
  cell = smartlist_get(codec.encoder.ready_cells, 0);
  tt_mem_op(cell->payload, OP_EQ, EXPECTED_CELL_PAYLOAD,
            sizeof(EXPECTED_CELL_PAYLOAD) - 1);

 done:
  relay_msg_codec_clear(&codec);
  relay_msg_clear(&msg);
}

static void
test_packing_valid_v1(void *arg)
{
  const cell_t *cell = NULL;
  relay_msg_t msg;
  relay_msg_t *packed_msg = tor_malloc_zero(sizeof(*packed_msg));
  uint8_t payload[4] = { 'A', 'b', 'C', 'd' };
  relay_msg_codec_t codec;

  (void) arg;

  relay_msg_codec_init(&codec, 1);

  /* Setup the message to queue for packing. */
  relay_msg_set(codec.relay_cell_proto, RELAY_COMMAND_CONFLUX_SWITCH, 0,
                payload, sizeof(payload), packed_msg);
  tt_int_op(packed_msg->relay_cell_proto, OP_EQ, 1);
  tt_int_op(packed_msg->length, OP_EQ, sizeof(payload));
  tt_int_op(packed_msg->command, OP_EQ, RELAY_COMMAND_CONFLUX_SWITCH);
  tt_int_op(packed_msg->stream_id, OP_EQ, 0);
  tt_mem_op(packed_msg->body, OP_EQ, payload, packed_msg->length);
  relay_msg_queue_packable(&codec, packed_msg);

  /* Setup the data cell for which the packed cell will be put before. */
  relay_msg_set(codec.relay_cell_proto, RELAY_COMMAND_DATA, 42,
                payload, sizeof(payload), &msg);
  tt_int_op(msg.relay_cell_proto, OP_EQ, 1);
  tt_int_op(msg.length, OP_EQ, sizeof(payload));
  tt_int_op(msg.command, OP_EQ, RELAY_COMMAND_DATA);
  tt_int_op(msg.stream_id, OP_EQ, 42);
  tt_mem_op(msg.body, OP_EQ, payload, msg.length);

  const uint8_t EXPECTED_CELL_PAYLOAD[] =
    // Relay cell header.
    "\x00\x00"                     // recognized
    "\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00" // digest

    // First message: RELAY_COMMAND_CONFLUX_SWITCH
    "\x16"              // command
    "\x00\x04"          // length
    "\x41\x62\x43\x64"  // payload

    // Second message: RELAY_COMMAND_DATA
    "\x02"              // command
    "\x00\x04"          // length
    "\x00\x2A"          // (optional) stream id
    "\x41\x62\x43\x64"  // payload

    // End of cell.
    "\x00"              // End of Message marker.
    "\x00\x00\x00\x00"; // zero pading.

  bool ret = relay_msg_encoder_add_msg(&codec, &msg);
  tt_assert(ret);

  tt_int_op(smartlist_len(codec.encoder.ready_cells), OP_EQ, 1);
  cell = smartlist_get(codec.encoder.ready_cells, 0);
  tt_mem_op(cell->payload, OP_EQ, EXPECTED_CELL_PAYLOAD,
            sizeof(EXPECTED_CELL_PAYLOAD) - 1);

  /* Make sure the packable cell was consumed. */
  tt_int_op(smartlist_len(codec.pending_packable_msg), OP_EQ, 0);

 done:
  relay_msg_codec_clear(&codec);
  relay_msg_clear(&msg);
}

static void
test_packing_invalid_v1(void *arg)
{
  (void) arg;

#ifndef ALL_BUGS_ARE_FATAL
  relay_msg_t legit_msg;
  relay_msg_codec_t codec;

  relay_msg_codec_init(&codec, 1);

  const uint8_t payload[4] = { 'A', 'b', 'C', 'd' };
  relay_msg_t packed_msg;
  /* Attempt to queue a non packable message. */
  packed_msg.command = RELAY_COMMAND_DATA;
  tor_capture_bugs_(1);
  relay_msg_queue_packable(&codec, &packed_msg);
  tt_int_op(smartlist_len(tor_get_captured_bug_log_()), OP_EQ, 1);
  tt_str_op(smartlist_get(tor_get_captured_bug_log_(), 0), OP_EQ,
            "!(!relay_command_is_packable(msg->command))");
  tor_end_capture_bugs_();

  /* We'll queue too many packable cells. 150 cells of 4 bytes of payload is
   * more than too many for a single cell. */
  for (int i = 0; i < 150; i++) {
    relay_msg_t *msg = tor_malloc_zero(sizeof(*msg));
    relay_msg_set(codec.relay_cell_proto, RELAY_COMMAND_XON, 42,
                  payload, sizeof(payload), msg);
    relay_msg_queue_packable(&codec, msg);
  }
  tt_int_op(smartlist_len(codec.pending_packable_msg), OP_EQ, 150);

  /* Setup a legit message to trigger the packing. */
  relay_msg_set(codec.relay_cell_proto, RELAY_COMMAND_DATA, 42,
                payload, sizeof(payload), &legit_msg);

  tor_capture_bugs_(1);
  bool ret = relay_msg_encoder_add_msg(&codec, &legit_msg);
  tt_assert(!ret);
  tt_int_op(smartlist_len(tor_get_captured_bug_log_()), OP_EQ, 1);
  tt_str_op(smartlist_get(tor_get_captured_bug_log_(), 0), OP_EQ,
            "!(total_len > available_len)");

 done:
  relay_msg_codec_clear(&codec);
  relay_msg_clear(&legit_msg);
  tor_end_capture_bugs_();
#endif /* ALL_BUGS_ARE_FATAL */
}

struct testcase_t relay_msg_tests[] = {
  { "decoder_invalid_v1", test_decoder_invalid_v1, TT_FORK, NULL, NULL },

  { "decoder_valid_v0", test_decoder_valid_v0, TT_FORK, NULL, NULL },
  { "decoder_valid_v1", test_decoder_valid_v1, TT_FORK, NULL, NULL },

  { "encoder_valid_v0", test_encoder_valid_v0, TT_FORK, NULL, NULL },
  { "encoder_valid_v1", test_encoder_valid_v1, TT_FORK, NULL, NULL },

  { "packing_valid_v1", test_packing_valid_v1, TT_FORK, NULL, NULL },
  { "packing_invalid_v1", test_packing_invalid_v1, TT_FORK, NULL, NULL },

  END_OF_TESTCASES
};
