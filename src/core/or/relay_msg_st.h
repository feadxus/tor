/* Copyright (c) 2023, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file relay_msg_st.h
 * @brief A relay message which contains a relay command and parameters,
 *        if any, that is from a relay cell.
 **/

#ifndef TOR_RELAY_MSG_ST_H
#define TOR_RELAY_MSG_ST_H

#include "core/or/or.h"

/** A relay message object which contains pointers to the header and payload.
 *
 * One acquires a relay message through the use of an iterator. Once you get a
 * reference, the getters MUST be used to access data.
 *
 * This CAN NOT be made opaque so to avoid heap allocation in the fast path. */
typedef struct relay_msg_t {
  /* Relay cell protocol version of this message. */
  uint8_t relay_cell_proto;
  /* Relay command of a message. */
  uint8_t command;
  /* Length of payload. */
  uint16_t length;
  /* Optional routing header: stream ID of a message or 0. */
  streamid_t stream_id;
  /* Indicate if this is a message from a relay early cell. */
  bool is_relay_early;
  /* Message body of a relay message. */
  uint8_t *body;
} relay_msg_t;

/** Decoder object for which cells (cell_t) are given and then unframed into
 * relay message(s) kept in this object. */
typedef struct relay_msg_decoder_t {
  /* Version of the relay cell protocol to use for this decoder. */
  uint8_t relay_cell_proto;
  /* The pending relay message meaning that it needs more cell to be completed.
   * This happens when messages are fragmented over many cells. */
  relay_msg_t *pending;
  /* The length of the pending data we are waiting for. In other words, how
   * many bytes do we need more in more cells to complete the message body. */
  size_t pending_len;
  /* The list of messages that are ready. Multiple messages can be in one
   * single cell and so this list will have them once unframed. */
  smartlist_t *ready;
} relay_msg_decoder_t;

/** Encoder object for which relay messages are given and then packed or/and
 * fragmented yielding cell(s) to be sent on the wire. */
typedef struct relay_msg_encoder_t {
  /* Version of the relay cell protocol of this encoded. */
  uint8_t relay_cell_proto;
  /* Cells that are ready to be sent on the wire. */
  smartlist_t *ready_cells;
} relay_msg_encoder_t;

/** Codec object for relay message. This contains the decoder to be used for
 * relay message. */
typedef struct relay_msg_codec_t {
  /* Version of the relay cell protocol of this codec. */
  uint8_t relay_cell_proto;
  /* The decoder. */
  relay_msg_decoder_t decoder;
  /* The encoded . */
  relay_msg_encoder_t encoder;
  /* A list of relay message that are awaiting to be packed. A message is
   * popped everytime a cell goes through the encoder. */
  smartlist_t *pending_packable_msg;
} relay_msg_codec_t;

#endif /* !defined(TOR_RELAY_MSG_ST_H) */
