/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <msgpack.h>

#include "collectx.h"

#define SO_NAME "/opt/mellanox/collectx/lib/providers/libevent_fluent_aggreagator.so"

int load_clx_callback(struct flb_collectx *ctx, const char* so_lib_name)
{
    if (so_lib_name == NULL || strlen(so_lib_name) == 0) {
        flb_plg_error(ctx->ins, "so_lib_name is empty!");
        return -1;
    }

    ctx->clx_provider_handle = dlopen(so_lib_name, RTLD_NOW);
	if (ctx->clx_provider_handle == NULL) {
        flb_plg_error(ctx->ins, "cannot load shared obj from '%s'. Error: '%s'", so_lib_name, dlerror());
        return -1;
    }

    ctx->cb_write_events_to_clx = (clx_callback_t)dlsym(ctx->clx_provider_handle, "cb_wtite_events_to_clx");
    return 0;
}


static int cb_collectx_init(struct flb_output_instance *ins,
                            struct flb_config *config, void *data)
{
    int ret;
    struct flb_collectx *ctx = NULL;
    (void) config;

    ctx = flb_calloc(1, sizeof(struct flb_collectx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins                   = ins;
    ctx->collectx_provider_ctx = data;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    ret = load_clx_callback(ctx, (char*) SO_NAME);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;
}


static void cb_collectx_flush(const void *data, size_t bytes,
                             const char *tag, int tag_len,
                             struct flb_input_instance *i_ins,
                             void *out_context,
                             struct flb_config *config)
{
    struct flb_collectx *ctx = out_context;
    char *buf = NULL;
    (void) i_ins;
    (void) config;

    /* A tag might not contain a NULL byte */
    buf = flb_malloc(tag_len + 1);
    if (!buf) {
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    memcpy(buf, tag, tag_len);
    buf[tag_len] = '\0';

    int status = ctx->cb_write_events_to_clx(ctx->collectx_provider_ctx, data, bytes);
    if (status != 0) {
        flb_errno();
        flb_plg_error(ctx->ins, "write_events_to_clx failed with status %d!", status);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    free(buf);
    FLB_OUTPUT_RETURN(FLB_OK);
}


static int cb_collectx_exit(void *data, struct flb_config *config)
{
    struct flb_collectx *ctx = data;

    if (ctx != NULL) {
        if (ctx->clx_provider_handle != NULL) {
            dlclose(ctx->clx_provider_handle);
        }
        flb_free(ctx);
    }
    return 0;
}


/* Configuration properties map */
static struct flb_config_map config_map[] = {
    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_collectx_plugin = {
    .name         = "collectx",
    .description  = "Pushes events into Collectx on demand",
    .cb_init      = cb_collectx_init,
    .cb_flush     = cb_collectx_flush,
    .cb_exit      = cb_collectx_exit,
    .flags        = 0,
    .config_map   = config_map
};
