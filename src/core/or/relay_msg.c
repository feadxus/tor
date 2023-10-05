/* Copyright (c) 2023, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay_msg.c
 * \brief XXX: Write a brief introduction to this module.
 **/

#define RELAY_MSG_PRIVATE

#include "app/config/config.h"

#include "core/or/cell_st.h"
#include "core/or/relay.h"
#include "core/or/relay_cell.h"
#include "core/or/relay_msg.h"

#include "feature/nodelist/networkstatus.h"

#include "lib/log/util_bug.h"

/* Size of a relay message header which is up to the payload. */
#define RELAY_MSG_HEADER_SIZE_V0 (0)
#define RELAY_MSG_HEADER_SIZE_V1 (1 + 2)
/* Size of a relay message routing header. */
#define RELAY_MSG_ROUTING_HEADER_SIZE_V1 (2)
/* End of relay message marker as per the specification. */
#define RELAY_MSG_END_MARKER_V1 (0)

/* Consensus parameters. Updated when we get a new consensus. */
static bool relay_msg_enabled = false;

/** Return the UseRelayMessage value either from the configuration file or the
 * consensus if not present. */
static bool
get_param_enabled(const networkstatus_t *ns)
{
#define RELAY_MSG_PARAM_ENABLED_DEFAULT (0)
#define RELAY_MSG_PARAM_ENABLED_MIN (0)
#define RELAY_MSG_PARAM_ENABLED_MAX (1)

  if (get_options()->UseRelayMessage != -1) {
    return get_options()->UseRelayMessage != 0;
  }

  return networkstatus_get_param(ns, "UseRelayMessage",
                                 RELAY_MSG_PARAM_ENABLED_DEFAULT,
                                 RELAY_MSG_PARAM_ENABLED_MIN,
                                 RELAY_MSG_PARAM_ENABLED_MAX) != 0;
}

/** Return true iff the given command is allowed to have a stream ID of 0. */
static inline bool
relay_command_requires_stream_id(const uint8_t cmd)
{
  /* In accordance to proposal 340. */
  switch (cmd) {
  case RELAY_COMMAND_BEGIN:
  case RELAY_COMMAND_BEGIN_DIR:
  case RELAY_COMMAND_CONNECTED:
  case RELAY_COMMAND_DATA:
  case RELAY_COMMAND_END:
  case RELAY_COMMAND_RESOLVE:
  case RELAY_COMMAND_RESOLVED:
  case RELAY_COMMAND_XOFF:
  case RELAY_COMMAND_XON:
    return true;
  default:
    return false;
  }
}

/** Return the relay message header size based on the given command and relay
 * cell protocol version. */
static size_t
get_relay_msg_header_size(const uint8_t cmd, const uint8_t relay_cell_proto)
{
  switch (relay_cell_proto) {
  case 0:
    return RELAY_MSG_HEADER_SIZE_V0;
  case 1:
  {
    size_t size = RELAY_MSG_HEADER_SIZE_V1;
    if (relay_command_requires_stream_id(cmd)) {
      size += RELAY_MSG_ROUTING_HEADER_SIZE_V1;
    }
    return size;
  }
  default:
    tor_assert_unreached();
    return 0;
  }
}

/** Return the maximum size of a relay message body that is allowed for the
 * given command and the relay cell protocol. */
static size_t
get_relay_msg_max_body(const uint8_t cmd, const uint8_t relay_cell_proto)
{
  switch (cmd) {
    /* DATAGRAM command will be allowed to be above a full cell. */
  default:
    return relay_cell_get_payload_size(relay_cell_proto) -
           get_relay_msg_header_size(cmd, relay_cell_proto);
  }
}

/** Return the encoded length of the given relay message. */
static size_t
get_relay_msg_encoded_len(const relay_msg_t *msg)
{
  return msg->length +
         get_relay_msg_header_size(msg->command, msg->relay_cell_proto);
}

/** Return the length of all packable message in the given codec queue. */
static size_t
get_packable_msg_encoded_len(const relay_msg_codec_t *codec)
{
  size_t len = 0;
  SMARTLIST_FOREACH_BEGIN(codec->pending_packable_msg,
                          const relay_msg_t *, msg) {
    len += get_relay_msg_encoded_len(msg);
  } SMARTLIST_FOREACH_END(msg);
  return len;
}

/** Parse the relay message header from the given payload and sets the value in
 * the relay message.
 *
 * Return the length parsed from the payload or -1 on error. */
static ssize_t
parse_relay_msg_hdr_v1(const uint8_t *payload, relay_msg_t *msg)
{
  size_t offset = 0;

  /* Relay Command. */
  msg->command = get_uint8(payload);
  offset += (sizeof(msg->command));
  /* Error immediately if this is an unknown relay command. Don't parse
   * anything else as we have an invalid payload in our hands. */
  if (!is_known_relay_command(msg->command)) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Unknown relay command %d. Invalid v1 cell.", msg->command);
    return -1;
  }
  /* Message body length. */
  msg->length = ntohs(get_uint16(payload + offset));
  offset += (sizeof(msg->length));
  /* Message body length validation. */
  if (msg->length > get_relay_msg_max_body(msg->command, 1)) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Relay message body length is too big: %u vs %zu. Invalid v1 cell.",
           msg->length, get_relay_msg_max_body(msg->command, 1));
    return -1;
  }

  return offset;
}

/** Parse the relay message routing header and set the relay message with it if
 * need be.
 *
 * Return the length parsed from the payload. */
static size_t
parse_relay_msg_routing_hdr_v1(const uint8_t *payload, relay_msg_t *msg)
{
  size_t offset = 0;

  if (relay_command_requires_stream_id(msg->command)) {
    msg->stream_id = ntohs(get_uint16(payload));
    offset += sizeof(msg->stream_id);
  } else {
    msg->stream_id = 0;
  }

  return offset;
}

/** Initialize the given encoder for the relay cell protocol version. */
static void
encoder_relay_msg_init(relay_msg_encoder_t *encoder, uint8_t relay_cell_proto)
{
  tor_assert(encoder);
  encoder->relay_cell_proto = relay_cell_proto;
  encoder->ready_cells = smartlist_new();
}

/** Clear a given encoder which frees its ressources. */
static void
encoder_relay_msg_clear(relay_msg_encoder_t *encoder)
{
  tor_assert(encoder);
  SMARTLIST_FOREACH(encoder->ready_cells, cell_t *, c, tor_free(c));
  smartlist_free(encoder->ready_cells);
}

/** Initialize a given decoder object for the relay cell protocol version. */
static void
decoder_relay_msg_init(relay_msg_decoder_t *decoder, uint8_t relay_cell_proto)
{
  memset(decoder, 0, sizeof(relay_msg_decoder_t));
  decoder->relay_cell_proto = relay_cell_proto;
  decoder->ready = smartlist_new();
}

/** Clear the inside of the given decoder object as in free any ressources. */
static void
decoder_relay_msg_clear(relay_msg_decoder_t *decoder)
{
  if (!decoder) {
    return;
  }
  relay_msg_free(decoder->pending);
  SMARTLIST_FOREACH(decoder->ready, relay_msg_t *, m, relay_msg_free(m));
  smartlist_free(decoder->ready);
}

/** Clear the given decoder as in free all its content and initialize it to
 * factory default. */
static void
decoder_relay_msg_reset(relay_msg_decoder_t *decoder)
{
  uint8_t relay_cell_proto = decoder->relay_cell_proto;
  decoder_relay_msg_clear(decoder);
  decoder_relay_msg_init(decoder, relay_cell_proto);
}

/** Move the pending relay message to the ready list. Final validation is done
 * to the relay message and returns true if valid or false if not. */
static bool
decoder_mark_pending_ready(relay_msg_decoder_t *decoder)
{
  tor_assert(decoder);
  tor_assert(decoder->pending_len == 0);
  tor_assert(decoder->pending);

  smartlist_add(decoder->ready, decoder->pending);
  decoder->pending = NULL;

  return true;
}

/** Unframe a cell for relay cell protocol v0, which is anything before
 * RelayCell protocol version appeared, and put it into the decoder.
 *
 * Return true on success else false indicating the cell is invalid. */
static bool
decoder_unframe_cell_v0(const cell_t *cell, relay_msg_decoder_t *decoder)
{
  bool ret = false;
  relay_header_t rh;

  /* First thing in the payload is the header. Notice that we use this function
   * here and our own and reason is that this function is used also to get the
   * digest and recognized field and so instead of doing a new clean one, we
   * stick to the same interface for header parsing. */
  relay_header_unpack(&rh, cell->payload);

  /* Invalid length. */
  if (rh.length > RELAY_PAYLOAD_SIZE) {
    goto end;
  }

  /* Invalid relay command. */
  if (!is_known_relay_command(rh.command)) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Unknown relay command %d. Invalid cell.", rh.command);
    goto end;
  }

  /* Allocate new relay message. We'll copy data from the given cell. */
  decoder->pending = tor_malloc_zero(sizeof(relay_msg_t));
  decoder->pending_len = 0;
  decoder->pending->relay_cell_proto = 0;
  decoder->pending->is_relay_early = cell->command == CELL_RELAY_EARLY;

  /* Set up the header information and body. */
  decoder->pending->command = rh.command;
  decoder->pending->length = rh.length;
  decoder->pending->stream_id = rh.stream_id;
  decoder->pending->body = tor_malloc_zero(rh.length);

  /* Copy the cell payload into the message body. */
  const size_t header_size =
    relay_cell_get_header_size(decoder->relay_cell_proto);
  memcpy(decoder->pending->body, cell->payload + header_size, rh.length);

  /* This pending is now ready. */
  decoder_mark_pending_ready(decoder);

  /* Success. */
  ret = true;

 end:
  return ret;
}

/** Unframe a cell for relay cell protocol v1 and put it into the decoder.
 *
 * Return true on success else false indicating the cell is invalid. */
static bool
decoder_unframe_cell_v1(const cell_t *cell, relay_msg_decoder_t *decoder)
{
/** Helper macro: Used ONLY in relay_msg_decoder_add_cell() to make sure the
 * length of data we are about to parse fits within the maximum size of a
 * payload. On error, it protocol warns and goto end. */
#undef CHECK_AVAILABLE_ROOM
#define CHECK_AVAILABLE_ROOM(wanted_len)                                  \
  do {                                                                    \
    if ((processed_len + wanted_len) > PAYLOAD_MAX_SIZE) {                \
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,                              \
             "Cell is malformed. Missing data to build a relay message"); \
      goto end;                                                           \
    }                                                                     \
  } while (0)

  /* Returned value defaults on false as in a failure. */
  bool ret = false;

  tor_assert(cell);
  tor_assert(decoder);

  /* Maximum size the relay message payload can be (this includes the message
   * header(s). */
  const uint16_t PAYLOAD_MAX_SIZE =
    relay_cell_get_payload_size(decoder->relay_cell_proto);
  /* Pointer to the cell payload that is the start to the relay message data
   * Its content and position can't be changed, we always only offset in it. */
  const uint8_t * const payload = cell->payload +
    relay_cell_get_header_size(decoder->relay_cell_proto);

  /* Processed length of the payload. This is used to offset in the payload and
   * know if we have reached the end of the payload so to not overrun. */
  size_t processed_len = 0;
  /* This is the current relay message we are processing during the loop. */
  relay_msg_t *current = NULL;

  /* As long as we have bytes to consume. */
  while (processed_len < PAYLOAD_MAX_SIZE) {
    /* Peek in the payload for an end-of-message marker.
     *
     * We first check if we have available room to do this and won't buffer
     * overrun.
     *
     * Also, we don't check if this is the start of the payload because a
     * marker on the first byte is not allowed. Furthermore, we can't do it
     * with a pending length because it means the pending message is not
     * complete and thus it can NOT be an end marker if we find one. */
    CHECK_AVAILABLE_ROOM(sizeof(uint8_t));
    if (get_uint8(payload + processed_len) == RELAY_MSG_END_MARKER_V1) {
      /* End-of-message marker are not allowed at the very start of a cell
       * because this means a cell without a message. Invalid. */
      if (processed_len == 0) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "End-of-message marker at the start. Invalid v1 cell.");
        goto end;
      }
      /* We done parsing this cell. */
      break;
    }

    /* Use the pending message if any. If not, we'll build a new one. */
    current = decoder->pending;
    if (!current) {
      /* No pending message, the length has to be 0 else bad code flow. */
      tor_assert(decoder->pending_len == 0);

      /* Without a pending message, we are about to parse a new relay message
       * header and so make sure we have enough room for this else this is a
       * malformed cell. A header can't be fragmented. */
      CHECK_AVAILABLE_ROOM(RELAY_MSG_HEADER_SIZE_V1);

      /* We have enough room to parse the header, allocate the object. At this
       * stage, the message body is NOT allocated yet. */
      current = tor_malloc_zero(sizeof(relay_msg_t));
      current->relay_cell_proto = 1;

      /* Only consider this flag if we haven't already flagged it. Reason is
       * that we only allow one relay_early command per message else we would
       * deplete our bucket for a fragmented message over multiple cells. */
      if (!current->is_relay_early) {
        current->is_relay_early = cell->command == CELL_RELAY_EARLY;
      }

      /* Parse the relay message header into the relay message. Again, no body
       * allocated yet. */
      ssize_t parsed_len =
        parse_relay_msg_hdr_v1(payload + processed_len, current);
      if (parsed_len < 0) {
        goto end;
      }
      processed_len += (size_t) parsed_len;

      /* Then, check if the command requires a stream ID for which we parse the
       * message routing header. */
      if (relay_command_requires_stream_id(current->command)) {
        /* Validate we have enough room for the routing header. */
        CHECK_AVAILABLE_ROOM(RELAY_MSG_ROUTING_HEADER_SIZE_V1);

        /* Parse the routing header into the relay message. */
        parsed_len =
          parse_relay_msg_routing_hdr_v1(payload + processed_len, current);
        processed_len += parsed_len;
      }

      /* Allocate the message body. The length is bound by its type of 16 bit
       * and so the maximum value is UINT16_MAX which is allowed. */
      current->body = tor_malloc_zero(current->length);

      /* Set this new message as pending. Next step is to get the body. */
      decoder->pending_len = current->length;
      decoder->pending = current;
    }

    /* The body length is the minimum between what is left and what we want as
     * in the pending length in the decoder. */
    uint16_t body_len = MIN(decoder->pending_len,
                            PAYLOAD_MAX_SIZE - processed_len);
    /* Safety: The body_len should always fit within what was processed and the
     * maximum size. However, this function is so delicate that there are never
     * too many checks for buffer overrun. Future proof ourselves. */
    CHECK_AVAILABLE_ROOM(body_len);

    /* We can end up in a situation where the length is 0 because the relay
     * command doesn't require a body or the body is fragmented in other cells
     * because we reached the end of the cell. In that case, avoid useless
     * mempcy of 0 length. */
    if (body_len > 0) {
      memcpy(current->body, payload + processed_len, body_len);
      processed_len += body_len;
      decoder->pending_len -= body_len;
    }

    /* If we have the entire message, mark it ready and continue processing. */
    if (decoder->pending_len == 0) {
      decoder_mark_pending_ready(decoder);
    }
  }

  /* Success. */
  ret = true;

 end:
  /* On error, we cleanup the decoder and anything allocated so the caller
   * can't by mistake use that data. */
  if (!ret) {
    /* Make sure we were not processing the pending message. */
    if (decoder->pending == current) {
      decoder->pending = NULL;
    }
    relay_msg_free(current);
    decoder_relay_msg_reset(decoder);
  }
  return ret;
}

/** Encode into the given payload the body of the message. Make sure we won't
 * overrun the maximum allowed body size. */
static void
encode_relay_msg_body(const relay_msg_t *msg, uint8_t *payload)
{
  /* Code flow error reaching this point. */
  tor_assert(msg->length <=
             get_relay_msg_max_body(msg->command, msg->relay_cell_proto));
  memcpy(payload, msg->body, msg->length);
}

/** Encode relay message for relay cell protocol version 0.
 *
 * Return the length of the encoded message. */
static void
encode_relay_msg_v0(const relay_msg_t *msg, relay_msg_codec_t *codec)
{
  relay_header_t rh;
  cell_t *cell = tor_malloc_zero(sizeof(*cell));

  memset(&rh, 0, sizeof(rh));

  /* Construct part of the relay cell header. */
  cell->command = CELL_RELAY;
  cell->relay_cell_proto = 0;

  /* Construct the relay message header. */
  rh.command = msg->command;
  rh.stream_id = msg->stream_id;
  rh.length = msg->length;

  /* Pack header. */
  relay_header_pack(cell->payload, &rh);

  /* Code flow error reaching this point. */
  tor_assert(msg->length <=
             get_relay_msg_max_body(msg->command, msg->relay_cell_proto));

  /* Set payload which also takes care of padding. */
  relay_cell_set_payload(cell, msg->body, msg->length);

  /* Put the cell in the ready queue, it is ready to be sent. */
  smartlist_add(codec->encoder.ready_cells, cell);
}

/** Encode the given relay message into the given payload of size payload_len.
 *
 * Return the number of encoded bytes on success else 0 on error indicating the
 * payload has not enough room. The payload is zeroed for safety purposes in
 * that case. */
static size_t
encode_one_relay_msg_v1(const relay_msg_t *msg, uint8_t *payload,
                        const size_t payload_len)
{
/* Helper macro to check for available room in the payload. The caller of this
 * function should always check that the message fits in the given payload but
 * we are never too careful in the world of C-live-ammo. */
#undef CHECK_AVAILABLE_ROOM
#define CHECK_AVAILABLE_ROOM(__wanted_len)            \
  do {                                                \
    if (BUG((offset + __wanted_len) > payload_len)) { \
      goto error;                                     \
    }                                                 \
  } while (0)

  size_t offset = 0;

  /* Relay message header. First the command. */
  CHECK_AVAILABLE_ROOM(sizeof(uint8_t));
  set_uint8(payload, msg->command);
  offset += sizeof(msg->command);
  /* Second the length of the body. */
  CHECK_AVAILABLE_ROOM(sizeof(uint16_t));
  set_uint16(payload + offset, htons(msg->length));
  offset += sizeof(msg->length);

  /* Optional routing header. */
  if (relay_command_requires_stream_id(msg->command)) {
    /* Safety checks, sending a value of 0 would be a protocol violation. */
    if (BUG(msg->stream_id == 0)) {
      goto error;
    }
    CHECK_AVAILABLE_ROOM(sizeof(uint16_t));
    set_uint16(payload + offset, htons(msg->stream_id));
    offset += sizeof(msg->stream_id);
  }

  /* Put the message body into the payload. */
  CHECK_AVAILABLE_ROOM(msg->length);
  encode_relay_msg_body(msg, payload + offset);
  offset += msg->length;

  return offset;

 error:
  memset(payload, 0, payload_len);
  return 0;
}

/** Encode relay message for using the given codec for protocol version 1. This
 * function will opportunistically pack pending cells along the given message.
 *
 * Return the length of the encoded message on success. On error, 0 is
 * returned. */
static size_t
encode_relay_msg_v1(const relay_msg_t *msg, relay_msg_codec_t *codec)
{
/* Useful macro to advance our variables but also check for overflow. */
#undef ADVANCE_CHECKED
#define ADVANCE_CHECKED(__wanted_len)         \
  do {                                        \
    if (BUG(__wanted_len > available_len)) {  \
      goto error;                             \
    }                                         \
    offset += __wanted_len;                   \
    encoded_len += __wanted_len;              \
    available_len -= __wanted_len;            \
  } while (0)

  size_t len;

  /* We use this value through out this function so keep it const. */
  const size_t max_payload_size =
    relay_cell_get_payload_size(codec->relay_cell_proto);

  /* XXX: We allocate the cell at the moment in order to queue it in the
   * encoder ready list. We could think of a future change where we have
   * pre-allocated cells in the encoder that we would reuse instead. */
  cell_t *cell = tor_malloc_zero(sizeof(*cell));

  /* Construct part of the relay cell header. The circuit id is set before
   * sending on the actual circuit. */
  cell->command = CELL_RELAY;
  cell->relay_cell_proto = codec->relay_cell_proto;

  /* First field of the relay cell header: recognized. */
  set_uint16(cell->payload, 0);
  /* Digest is set before sending once the payload is finalized. */

  /* How many bytes have we encoded in the cell payload. */
  size_t encoded_len = 0;

  /* This is the amount of bytes we have available for the relay message(s). It
   * changes through out this function and used for overflow checks. */
  size_t available_len = max_payload_size;

  /* Start encoding after the relay cell header. */
  size_t offset = relay_cell_get_header_size(codec->relay_cell_proto);

  /* We are looking to build a cell that contains at least this amount of
   * bytes. The message plus the pending packable cells. */
  size_t total_len = get_relay_msg_encoded_len(msg) +
                     get_packable_msg_encoded_len(codec);
  if (BUG(total_len > available_len)) {
    /* XXX There is a world I think where the maze could make this happen. If
     * we see this happening, we can try to fix the maze or declare that this
     * is fine and handle this case by creating a cell with all pending
     * packable cells and then creating a new cell for the message. For now, we
     * scream loudly to know if this happens organically through the maze. */
    goto error;
  }

  SMARTLIST_FOREACH_BEGIN(codec->pending_packable_msg,
                          const relay_msg_t *, pending_msg) {
    log_info(LD_CIRC, "Packing cell command %u of length %zu with data cell",
             pending_msg->command, get_relay_msg_encoded_len(pending_msg));
    /* Encoded the message in the cell offsetted to the available bytes. */
    len = encode_one_relay_msg_v1(pending_msg, cell->payload + offset,
                                  available_len);
    ADVANCE_CHECKED(len);
  } SMARTLIST_FOREACH_END(pending_msg);

  /* We have consumed all pending packable message(s), clear the list. */
  SMARTLIST_FOREACH(codec->pending_packable_msg, relay_msg_t *, m,
                    relay_msg_free(m));
  smartlist_clear(codec->pending_packable_msg);

  /* Finally, put in the actual message in the cell. We know there is enough
   * room due to the initial total_len check. */
  len = encode_one_relay_msg_v1(msg, cell->payload + offset, available_len);
  ADVANCE_CHECKED(len);

  /* Check if we at least have 1 byte available to add an end-of-message
   * marker. If not, the protocol allows the data to be exactly up to the end
   * meaning no need for a marker in that case. */
  if (available_len > 0) {
    set_uint8(cell->payload + offset, RELAY_MSG_END_MARKER_V1);
    ADVANCE_CHECKED(sizeof(uint8_t));
  }

  /* Pad the cell if needed. This function takes the payload size thus why we
   * remove the header size. */
  relay_cell_pad_payload(cell, encoded_len);

  /* Last step, put the cell in the ready queue, it is ready to be sent. */
  smartlist_add(codec->encoder.ready_cells, cell);
  return encoded_len;

 error:
  tor_free(cell);
  return 0;
}

/*
 * Public API
 */

/** Return true iff the ability to use relay messages is enabled. */
bool
relay_msg_is_enabled(void)
{
  return relay_msg_enabled;
}

/** Called just before the consensus is changed with the given networkstatus_t
 * object. */
void
relay_msg_consensus_has_changed(const networkstatus_t *ns)
{
  relay_msg_enabled = get_param_enabled(ns);
}

/** Free the given relay message. */
void
relay_msg_free(relay_msg_t *msg)
{
  if (!msg) {
    return;
  }
  tor_free(msg->body);
  tor_free(msg);
}

/** Clear a relay message as in free its content and reset all fields to 0.
 * This is useful for stack allocated memory. */
void
relay_msg_clear(relay_msg_t *msg)
{
  tor_assert(msg);
  tor_free(msg->body);
  memset(msg, 0, sizeof(*msg));
}

/** Initialize a given codec pointer for the relay cell protocol version. */
void
relay_msg_codec_init(relay_msg_codec_t *codec, uint8_t relay_cell_proto)
{
  tor_assert(codec);
  codec->relay_cell_proto = relay_cell_proto;
  decoder_relay_msg_init(&codec->decoder, relay_cell_proto);
  encoder_relay_msg_init(&codec->encoder, relay_cell_proto);
  codec->pending_packable_msg = smartlist_new();
}

/** Clear the content of the given codec object as in free the ressources. */
void
relay_msg_codec_clear(relay_msg_codec_t *codec)
{
  tor_assert(codec);
  decoder_relay_msg_clear(&codec->decoder);
  encoder_relay_msg_clear(&codec->encoder);
  SMARTLIST_FOREACH(codec->pending_packable_msg, relay_msg_t *, msg,
                    relay_msg_free(msg));
  smartlist_free(codec->pending_packable_msg);
}

/** Add a new cell to the decoder which unframes it and creates relay
 * message(s). They are accumulated inside the decoder and can be taken after
 * this process.
 *
 * This is a core function of the fast path processing all relay cells and
 * building messages. The caller should query the decoder for any completed
 * messages. If none are ready, it means more cells are needed to complete any
 * pending messages.
 *
 * Return true if the cell was successfully unframed and validated. Else return
 * false meaning the cell or the constructed message is invalid. */
bool
relay_msg_decode_cell(relay_msg_codec_t *codec, const cell_t *cell)
{
  tor_assert(cell);
  tor_assert(codec);

  /* This is set during decryption and so reaching this should always match. */
  tor_assert(cell->relay_cell_proto == codec->relay_cell_proto);

  switch (codec->relay_cell_proto) {
  case 0:
    return decoder_unframe_cell_v0(cell, &codec->decoder);
  case 1:
    return decoder_unframe_cell_v1(cell, &codec->decoder);
  default:
    /* In theory, we can't negotiate a protocol version we don't know but,
     * again, this is C and 20+ year old code base so be extra safe. */
    tor_assert_nonfatal_unreached();
    /* Consider invalid of course. */
    return false;
  }
}

/** Add a new message into the codec which can yield one or more cells. They
 * need to be taken after this if ready.
 *
 * Return true on success else false. */
bool
relay_msg_encode_msg(relay_msg_codec_t *codec, const relay_msg_t *msg)
{
  tor_assert(codec);
  tor_assert(msg);

  /* Extra safety code flow. */
  tor_assert(msg->relay_cell_proto == codec->relay_cell_proto);

  switch (codec->relay_cell_proto) {
  case 0:
    encode_relay_msg_v0(msg, codec);
    break;
  case 1:
    if (!encode_relay_msg_v1(msg, codec)) {
      goto error;
    }
    break;
  default:
    /* In theory, we can't negotiate a protocol version we don't know but,
     * again, this is C and 20+ year old code base so be extra safe. */
    tor_assert_nonfatal_unreached();
    goto error;
  }

  return true;

 error:
  return false;
}
