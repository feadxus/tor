/* Copyright (c) 2023, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay_msg.h
 * \brief Header file for relay_msg.c.
 **/

#ifndef TOR_RELAY_MSG_H
#define TOR_RELAY_MSG_H

#include "core/or/or.h"

#include "core/or/relay_msg_st.h"

bool relay_msg_is_enabled(void);

void relay_msg_consensus_has_changed(const networkstatus_t *ns);

/* Relay message */
void relay_msg_free(relay_msg_t *msg);
void relay_msg_clear(relay_msg_t *msg);
relay_msg_t *relay_msg_copy(const relay_msg_t *msg);
void relay_msg_set(const uint8_t relay_cell_proto, const uint8_t cmd,
                   const streamid_t streamd_id, const uint8_t *payload,
                   const uint16_t payload_len, relay_msg_t *msg);

/* Codec. */
void relay_msg_codec_init(relay_msg_codec_t *codec, uint8_t relay_cell_proto);
void relay_msg_codec_clear(relay_msg_codec_t *codec);
void relay_msg_queue_packable(relay_msg_codec_t *codec, relay_msg_t *msg);

/* Decoder/Encoder. */
bool relay_msg_decode_cell(relay_msg_codec_t *codec, const cell_t *cell);
bool relay_msg_encode_msg(relay_msg_codec_t *codec, const relay_msg_t *msg);

/* Consumer */
smartlist_t *relay_msg_take_ready_cells(relay_msg_codec_t *codec);
smartlist_t *relay_msg_take_ready_msgs(relay_msg_codec_t *codec);

/* Getters */
size_t relay_msg_get_next_max_len(const relay_msg_codec_t *codec,
                                  const uint8_t cmd);
relay_msg_codec_t *relay_msg_get_codec(circuit_t *circ, crypt_path_t *cpath);

#ifdef RELAY_MSG_PRIVATE

#endif /* RELAY_MSG_PRIVATE */

#endif /* TOR_RELAY_MSG_H */

