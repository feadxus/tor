/* Copyright (c) 2023, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay_cell.h
 * \brief Header file for relay_cell.c.
 **/

#ifndef TOR_RELAY_CELL_H
#define TOR_RELAY_CELL_H

#include "core/or/or.h"

#include "core/or/cell_st.h"

/** When padding a cell with randomness, leave this many zeros after the
 * payload. Historically, it has paid off to keep unused bytes after the
 * payload for the future of our C-tor maze and protocol. */
#define RELAY_CELL_PADDING_GAP 4

/* Getters. */
bool relay_cell_is_recognized(const cell_t *cell);
uint8_t *relay_cell_get_digest(cell_t *cell);
size_t relay_cell_get_digest_len(const cell_t *cell);

/* Setters. */
void relay_cell_set_payload(cell_t *cell, const uint8_t *payload,
                            size_t payload_len);
void relay_cell_set_digest(cell_t *cell, uint8_t *cell_digest);
void relay_cell_pad_payload(cell_t *cell, size_t payload_len);

/*
 * NOTE: The following are inlined for performance reasons. These values are
 * accessed everywhere and so, even if not expensive, we avoid a function call.
 */

/** Return the size of the relay cell header for the given relay cell
 * protocol version. */
static inline size_t
relay_cell_get_header_size(uint8_t relay_cell_proto)
{
  /* Specified in tor-spec.txt. */
  switch (relay_cell_proto) {
  case 0: return (1 + 2 + 2 + 4 + 2); // 11
  case 1: return (2 + 14); // 16
  default:
    tor_fragile_assert();
    return 0;
  }
}

/** Return the size of the relay cell payload for the given relay cell
 * protocol version. */
static inline size_t
relay_cell_get_payload_size(uint8_t relay_cell_proto)
{
  return CELL_PAYLOAD_SIZE - relay_cell_get_header_size(relay_cell_proto);
}

#ifdef RELAY_CELL_PRIVATE

STATIC size_t get_pad_cell_offset(size_t payload_len,
                                  uint8_t relay_cell_proto);

#endif /* RELAY_CELL_PRIVATE */

#endif /* TOR_RELAY_CELL_H */

