/* Copyright (c) 2023, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay_msg.c
 * \brief XXX: Write a brief introduction to this module.
 **/

#define RELAY_MSG_PRIVATE

#include "app/config/config.h"

#include "core/or/relay_msg.h"

#include "feature/nodelist/networkstatus.h"

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

/** Reset a given encoder that is set it back to its initial state. */
#if 0
static void
encoder_relay_msg_reset(relay_msg_encoder_t *encoder)
{
  tor_assert(encoder);
  uint8_t relay_cell_proto = encoder->relay_cell_proto;
  encoder_relay_msg_clear(encoder);
  encoder_relay_msg_init(encoder, relay_cell_proto);
}
#endif

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
#if 0
static void
decoder_relay_msg_reset(relay_msg_decoder_t *decoder)
{
  uint8_t relay_cell_proto = decoder->relay_cell_proto;
  decoder_relay_msg_clear(decoder);
  decoder_relay_msg_init(decoder, relay_cell_proto);
}
#endif

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
