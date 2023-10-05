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

/* Codec. */
void relay_msg_codec_init(relay_msg_codec_t *codec, uint8_t relay_cell_proto);
void relay_msg_codec_clear(relay_msg_codec_t *codec);

/* Decoder/Encoder. */
bool relay_msg_decode_cell(relay_msg_codec_t *codec, const cell_t *cell);

#ifdef RELAY_MSG_PRIVATE

#endif /* RELAY_MSG_PRIVATE */

#endif /* TOR_RELAY_MSG_H */

