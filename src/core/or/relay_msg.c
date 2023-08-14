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
