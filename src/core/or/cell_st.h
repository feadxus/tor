/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file cell_st.h
 * @brief Fixed-size cell structure.
 **/

#ifndef CELL_ST_H
#define CELL_ST_H

/** Parsed onion routing cell.  All communication between nodes
 * is via cells. */
struct cell_t {
  circid_t circ_id; /**< Circuit which received the cell. */
  uint8_t command; /**< Type of the cell: one of CELL_PADDING, CELL_CREATE,
                    * CELL_DESTROY, etc */
  /* Relay cell protocol version. This tells us which format to use when
   * parsing the payload. */
  uint8_t relay_cell_proto;
  uint8_t payload[CELL_PAYLOAD_SIZE]; /**< Cell body. */
};

#endif /* !defined(CELL_ST_H) */
