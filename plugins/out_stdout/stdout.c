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

#include "stdout.h"
#include "stdio.h"

//#define CHECK_RAW_MSGPACK_INPUT
//#define MEASURE_SPEED

static int cb_stdout_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    int ret;
    const char *tmp;
    struct flb_stdout *ctx = NULL;
    (void) ins;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_stdout));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
#ifdef MEASURE_SPEED
    ctx->ts_begin       = 0;
    ctx->ts_end         = 0;
    ctx->bytes_received = 0;
#endif // MEASURE_SPEED

#ifdef CHECK_RAW_MSGPACK_INPUT
    FILE *fp = fopen("/labhome/romanpr/workspace/git/fluent-bit/build/msgpackcheck.bin","wb");
    if (fp == NULL) {
         printf("cant open file for check binary output error\n");
    } else {
        ctx->check_in_raw_msgpack_fd = fileno(fp);
    }
#endif

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    ctx->out_format = FLB_PACK_JSON_FORMAT_NONE;
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        ret = flb_pack_to_json_format_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "unrecognized 'format' option. "
                          "Using 'msgpack'");
        }
        else {
            ctx->out_format = ret;
        }
    }

    /* Date key */
    ctx->date_key = ctx->json_date_key;
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp) {
        /* Just check if we have to disable it */
        if (flb_utils_bool(tmp) == FLB_FALSE) {
            ctx->date_key = NULL;
        }
    }

    /* Date format for JSON output */
    ctx->json_date_format = FLB_PACK_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "invalid json_date_format '%s'. "
                          "Using 'double' type", tmp);
        }
        else {
            ctx->json_date_format = ret;
        }
    }

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;
}

static uint64_t clx_parse_cpuinfo(void) {
    float f = 1.0;
    char buf[256];

    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        while (fgets(buf, 256, fp)) {
            if (!strncmp(buf, "model name", 10)) {
                char* p = strchr(buf, '@');
                if (p) {
                    sscanf(++p, "%f", &f);
                }
                break;
            }
        }
        fclose(fp);
    }
    if (f < 1.0) {
        f = 1.0;  // if cannot get correct frequency - use TSC
        printf("[warning] Could not get correct value of frequency. Values are in ticks.");
    } else {
        f *= 1.0e9;  // Value in 'model name' is in GHz
    }
    return (uint64_t)f;
}

static  uint64_t get_cpu_freq(void) {
#ifdef USE_SLEEP_TO_GET_CPU_FREQUENCY
    // Note:  Recent Intel CPUs have the TSC running at constant frequency.
    static uint64_t clock = 0;
    if (clock == 0) {
        uint64_t t_start = read_hres_clock();
        sleep(1);
        uint64_t t_end = read_hres_clock();
        clock = t_end - t_start;
    }
    return clock;
#else
    return clx_parse_cpuinfo();
#endif
}


static inline uint64_t read_hres_clock(void) {
    uint32_t low, high;
    asm volatile ("rdtsc" : "=a" (low), "=d" (high));
    return ((uint64_t)high << 32) | (uint64_t)low;
}


uint64_t clx_convert_cycles_to_usec(uint64_t cycles) {
    static uint64_t freq = 0;
    if (freq < 1) {
        // initialize once
        freq = get_cpu_freq();
        if (freq == 1) {
            freq = 1e6;  // time will be in ticks
        }
    }
    uint64_t ret = cycles * 1e6 / freq;
    return ret;
}


static void measure_recv_speed(const void *data, size_t bytes, struct flb_stdout *ctx) {
    if (ctx->ts_begin == 0) {
        // set ts_begin on first data
        ctx->ts_begin = read_hres_clock();
    }

    ctx->bytes_received += bytes;

    if (ctx->bytes_received > 100*1024*1024) {// update timers on every 2 Mb
        ctx->ts_end = read_hres_clock();
        uint64_t t_diff_clocks = ctx->ts_end - ctx->ts_begin;
        uint64_t time_diff = clx_convert_cycles_to_usec(t_diff_clocks);

        printf ("received %"PRIu64" bytes in %"PRIu64" usec\n", ctx->bytes_received, time_diff );

        ctx->bytes_received = 0;
        ctx->ts_begin = ctx->ts_end;
    }
}


static void cb_stdout_flush(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0, cnt = 0;
    struct flb_stdout *ctx = out_context;
    flb_sds_t json;
    char *buf = NULL;
    (void) i_ins;
    (void) config;

#ifdef MEASURE_SPEED
    measure_recv_speed(data, bytes, ctx);
#else  // MEASURE_SPEED

    struct flb_time tmp;
    msgpack_object *p;


    if (ctx->out_format != FLB_PACK_JSON_FORMAT_NONE) {
        json = flb_pack_msgpack_to_json_format(data, bytes,
                                               ctx->out_format,
                                               ctx->json_date_format,
                                               ctx->date_key);
        write(STDOUT_FILENO, json, flb_sds_len(json));
        flb_sds_destroy(json);

        /*
         * If we are 'not' in json_lines mode, we need to add an extra
         * breakline.
         */
        if (ctx->out_format != FLB_PACK_JSON_FORMAT_LINES) {
            printf("\n");
        }
        fflush(stdout);
    }
    else {
        /* A tag might not contain a NULL byte */
        buf = flb_malloc(tag_len + 1);
        if (!buf) {
            flb_errno();
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        memcpy(buf, tag, tag_len);
        buf[tag_len] = '\0';
        msgpack_unpacked_init(&result);
        while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
            //printf("[%zd] %s: [", cnt++, buf);
            //flb_time_pop_from_msgpack(&tmp, &result, &p);
            //printf("%"PRIu32".%09lu, ", (uint32_t)tmp.tm.tv_sec, tmp.tm.tv_nsec);
            // msgpack_object_print(stdout, *p);
            // printf("]\n");
            msgpack_object_print(stdout, result.data);
            printf("\n\n");
        }
        msgpack_unpacked_destroy(&result);
        flb_free(buf);
    }
    fflush(stdout);
#endif  // MEASURE_SPEED

#ifdef CHECK_RAW_MSGPACK_INPUT
            // to check that we recieved all data from in_raw_msgpack
            write(ctx->check_in_raw_msgpack_fd, data, bytes);
#endif

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_stdout_exit(void *data, struct flb_config *config)
{
    struct flb_stdout *ctx = data;
    if (!ctx) {
        return 0;
    }

    flb_free(ctx);
    return 0;
#ifdef CHECK_RAW_MSGPACK_INPUT
    close(ctx->check_in_raw_msgpack_fd);
#endif
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "format", NULL,
     0, FLB_FALSE, 0,
     "Specifies the data format to be printed. Supported formats are msgpack json, json_lines and json_stream."
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_format", NULL,
     0, FLB_FALSE, 0,
    "Specifies the name of the date field in output."
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_stdout, json_date_key),
    "Specifies the format of the date. Supported formats are double, iso8601 and epoch."
    },

    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_stdout_plugin = {
    .name         = "stdout",
    .description  = "Prints events to STDOUT",
    .cb_init      = cb_stdout_init,
    .cb_flush     = cb_stdout_flush,
    .cb_exit      = cb_stdout_exit,
    .flags        = 0,
    .config_map   = config_map
};
