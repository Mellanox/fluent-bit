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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include "in_raw_msgpack.h"
#include <sys/socket.h>
#include <sys/un.h>


int create_unix_sock(char *sock_path) {
    int socket_fd;
    struct sockaddr_un server_address;

    if ((socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
        printf("Failed to create client unix sock\n");
        return -1;
    }

    printf("Creating Unix Domain socket: %s,  socket=%d\n", sock_path, socket_fd);

    memset(&server_address, 0, sizeof(struct sockaddr_un));
    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, sock_path);
    // strcpy(server_address.sun_path, "./UDSDGCLNT");

    unlink(sock_path);
    if (bind(socket_fd, (const struct sockaddr *) &server_address, sizeof(struct sockaddr_un)) < 0) {
        close(socket_fd);
        printf("Failed to bind client unix sock\n");
        return -1;
    }
    return socket_fd;
}


int set_sock_fd(struct flb_raw_msgpack_config *ctx) {
    ctx->sock_fd = create_unix_sock(ctx->unix_sock_path);

    if (ctx->sock_fd < 0)
        printf("failed to create a socket\n");
        return -1;
    if ((listen(ctx->sock_fd, 5)) != 0) {
        printf("Listen failed...\n");
        return -1;
    }
    else
        printf("Server listening..\n");
    return 0;
}


static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static inline int pack_regex(msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck,
                             struct flb_raw_msgpack_config *ctx,
                             struct flb_time *t, char *data, size_t data_size)
{
    msgpack_pack_array(mp_pck, 2);
    flb_time_append_to_msgpack(t, mp_pck, 0);
    msgpack_sbuffer_write(mp_sbuf, data, data_size);

    return 0;
}

/* cb_collect callback */
static int in_raw_msgpack_collect(struct flb_input_instance *ins,
                            struct flb_config *config, void *in_context)
{

    int bytes = 0;
    int pack_size;
    int ret;
    char *pack;
    void *out_buf;
    size_t out_size;
    struct flb_time out_time;
    struct flb_raw_msgpack_config *ctx = in_context;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    // bytes = read(ctx->fd,
    //              ctx->buf + ctx->buf_len,
    //              sizeof(ctx->buf) - ctx->buf_len - 1);

    // bytes = read(ctx->sock_fd,
    //              ctx->sock_buf_bit + ctx->sock_buf_len,
    //              sizeof(ctx->sock_buf_bit) - ctx->sock_buf_len - 1);

    struct sockaddr_un client_address;
    socklen_t address_length  = sizeof(struct sockaddr_un);
    bytes = recvfrom(ctx->sock_fd,
                     (char *) &ctx->msg, sizeof(ctx->msg),
                     0, (struct sockaddr *) &client_address, &address_length);


    // printf("collect : received byte from socket: %d\n", bytes);
    int bytes_sent = sendto(ctx->sock_fd,
                            (char *) &ctx->msg, sizeof(ctx->msg),
                            0, (struct sockaddr *) &client_address, address_length);

    flb_plg_trace(ctx->ins, "stdin read() = %i", bytes);

    if (bytes == 0) {
        flb_plg_warn(ctx->ins, "end of file (stdin closed by remote end)");
    }

    if (bytes <= 0) {
        printf ("paused, cant recieve the data\n");
        flb_input_collector_pause(ctx->coll_fd, ctx->ins);
        flb_engine_exit(config);
        return -1;
    }
    // ctx->buf_len += bytes;
    // ctx->buf[ctx->buf_len] = '\0';
    // printf ("recieved handshake. ready to deal with real data: (ptr=%p , len=%d)\n", ctx->ptr, ctx->msg.data_len);
    flb_input_chunk_append_raw(ins, NULL, 0, ctx->ptr, ctx->msg.data_len);

    return 0;

    // /* Initialize local msgpack buffer */
    // msgpack_sbuffer_init(&mp_sbuf);
    // msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    // while (ctx->buf_len > 0) {
    //     // TBD(romanpr): do we need to check if we have read not entire buffer
    //     //printf ("buff of size %d: %s\n", ctx->buf_len, ctx->buf);
    //     flb_input_chunk_append_raw(ins, NULL, 0, ctx->buf, ctx->buf_len);
    //     ctx->buf_len = 0;
    //     // break;
    //     // if (!ctx->parser) {
    //     //     printf("no parser\n");
    //     //     ret = flb_pack_json_state(ctx->buf, ctx->buf_len,
    //     //                               &pack, &pack_size, &ctx->pack_state);
    //     //     if (ret == FLB_ERR_JSON_PART) {
    //     //         printf("ret == FLB_ERR_JSON_PART\n");
    //     //         flb_plg_debug(ctx->ins, "data incomplete, waiting for more...");
    //     //         msgpack_sbuffer_destroy(&mp_sbuf);
    //     //         return 0;
    //     //     }
    //     //     else if (ret == FLB_ERR_JSON_INVAL) {
    //     //         printf("ret == FLB_ERR_JSON_INVAL\n");
    //     //         flb_plg_debug(ctx->ins, "invalid JSON message, skipping");
    //     //         flb_pack_state_reset(&ctx->pack_state);
    //     //         flb_pack_state_init(&ctx->pack_state);
    //     //         ctx->pack_state.multiple = FLB_TRUE;
    //     //         ctx->buf_len = 0;
    //     //         msgpack_sbuffer_destroy(&mp_sbuf);
    //     //         return -1;
    //     //     }
    //     //     printf ("Process valid packaged records\n");
    //     //     /* Process valid packaged records */
    //     //     process_pack(&mp_pck, ctx, pack, pack_size);

    //     //     printf ("Move out processed bytes\n");
    //     //     /* Move out processed bytes */
    //     //     consume_bytes(ctx->buf, ctx->pack_state.last_byte, ctx->buf_len);
    //     //     ctx->buf_len -= ctx->pack_state.last_byte;
    //     //     ctx->buf[ctx->buf_len] = '\0';

    //     //     flb_pack_state_reset(&ctx->pack_state);
    //     //     flb_pack_state_init(&ctx->pack_state);
    //     //     ctx->pack_state.multiple = FLB_TRUE;

    //     //     flb_free(pack);

    //     //     printf ("append raw\n");
    //     //     flb_input_chunk_append_raw(ins, NULL, 0,
    //     //                                 mp_sbuf.data, mp_sbuf.size);
    //     //     msgpack_sbuffer_destroy(&mp_sbuf);
    //     //     printf ("returning\n");
    //     //     return 0;
    //     // }
    //     // else {
    //     //     printf("there is parser\n");
    //     //     /* Reset time for each line */
    //     //     flb_time_zero(&out_time);

    //     //     /* Use the defined parser */
    //     //     ret = flb_parser_do(ctx->parser, ctx->buf, ctx->buf_len,
    //     //                         &out_buf, &out_size, &out_time);
    //     //     if (ret >= 0) {
    //     //         if (flb_time_to_double(&out_time) == 0) {
    //     //             flb_time_get(&out_time);
    //     //         }
    //     //         pack_regex(&mp_sbuf, &mp_pck,
    //     //                    ctx, &out_time, out_buf, out_size);
    //     //         flb_free(out_buf);
    //     //         flb_input_chunk_append_raw(ins, NULL, 0,
    //     //                                    mp_sbuf.data, mp_sbuf.size);
    //     //         msgpack_sbuffer_clear(&mp_sbuf);
    //     //     }
    //     //     else {
    //     //         /* we need more data ? */
    //     //         flb_plg_trace(ctx->ins, "data mismatch or incomplete");
    //     //         msgpack_sbuffer_destroy(&mp_sbuf);
    //     //         return 0;
    //     //     }
    //     // }

    //     // if (ret == ctx->buf_len) {
    //     //     ctx->buf_len = 0;
    //     //     break;
    //     // }
    //     // else if (ret >= 0) {
    //     //     /*
    //     //      * 'ret' is the last byte consumed by the regex engine, we need
    //     //      * to advance it position.
    //     //      */
    //     //     ret++;
    //     //     consume_bytes(ctx->buf, ret, ctx->buf_len);
    //     //     ctx->buf_len -= ret;
    //     //     ctx->buf[ctx->buf_len] = '\0';
    //     // }
    // }

    // // msgpack_sbuffer_destroy(&mp_sbuf);
    // return 0;

}

static int config_destroy(struct flb_raw_msgpack_config *ctx)
{
    close(ctx->sock_fd);
    flb_free(ctx);
    return 0;
}


/* Initialize plugin */
static int in_raw_msgpack_init(struct flb_input_instance *in,
                         struct flb_config *config, void *data)
{
    int ret;
    const char *tmp;
    struct flb_raw_msgpack_config *ctx;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_raw_msgpack_config));
    if (!ctx) {
        return -1;
    }
    ctx->buf_len = 0;
    ctx->ins = in;
    // data pointer
    printf ("check init pointer %p\n", data);
    ctx->ptr = data;
    printf("pointer %p is set to be buffer pointer\n", ctx->ptr);

    // ctx->fd = fd;

    strncpy(ctx->unix_sock_path, "./fb_sock_server", sizeof(ctx->unix_sock_path));
    set_sock_fd(ctx);


    tmp = flb_input_get_property("parser", in);
    if (tmp) {
        ctx->parser = flb_parser_get(tmp, config);
        if (!ctx->parser) {
            flb_plg_error(ctx->ins, "requested parser '%s' not found", tmp);
        }
    }
    else {
        ctx->parser = NULL;
    }

    /* Always initialize built-in JSON pack state */
    flb_pack_state_init(&ctx->pack_state);
    ctx->pack_state.multiple = FLB_TRUE;

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_event(in,
                                        in_raw_msgpack_collect,
                                        ctx->sock_fd,
                                        config);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for STDIN input plugin");
        flb_free(ctx);
        return -1;
    }
    ctx->coll_fd = ret;

    return 0;
}

static int in_raw_msgpack_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_raw_msgpack_config *ctx = data;

    config_destroy(ctx);

    return 0;
}


struct flb_input_plugin in_raw_msgpack_plugin = {
    .name         = "raw_msgpack",
    .description  = "input raw Message Pack data",
    .cb_init      = in_raw_msgpack_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL, //in_raw_msgpack_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_raw_msgpack_exit
};
