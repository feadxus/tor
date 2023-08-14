/* Copyright (c) 2023, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay_msg.h
 * \brief Header file for relay_msg.c.
 **/

#ifndef TOR_RELAY_MSG_H
#define TOR_RELAY_MSG_H

#include "core/or/or.h"

bool relay_msg_is_enabled(void);

void relay_msg_consensus_has_changed(const networkstatus_t *ns);

#ifdef RELAY_MSG_PRIVATE

#endif /* RELAY_MSG_PRIVATE */

#endif /* TOR_RELAY_MSG_H */

