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
 *
 *  Modified Work:
 *
 *  Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 *  This software product is a proprietary product of NVIDIA CORPORATION &
 *  AFFILIATES (the "Company") and all right, title, and interest in and to the
 *  software product, including all associated intellectual property rights, are
 *  and shall remain exclusively with the Company.
 *
 *  This software product is governed by the End User License Agreement
 *  provided with the software product.
 *
 */

#include <stddef.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <msgpack.h>
#include <unistd.h>


typedef void* (*init_t)(const char*, const char*, const char*, void *, const char*);
typedef int* (*add_data_t)(void *, void *, int);
typedef int* (*finalize_t)(void *);


typedef struct fluentbit_param_pair_t {
    char* name;
    char* val;
} fluentbit_param_pair_t;


// keep this structure in C style
// input format for Collectx internal fluent-bit in-raw-msgpack
typedef struct fluentbit_export_parameters_t {
    int num_params;
    fluentbit_param_pair_t* params;
} fluentbit_export_parameters_t;



static inline
void pack_key_val_uint64(msgpack_packer *pk, const char* key, int key_len, const uint64_t val) {
    msgpack_pack_str(pk, key_len);
    msgpack_pack_str_body(pk, key, key_len);
    msgpack_pack_uint64(pk, val);
}


static inline
void pack_key_val_str(msgpack_packer *pk, const char* key, int key_len,
                             const char* val, int val_len) {
    msgpack_pack_str(pk, key_len);
    msgpack_pack_str_body(pk, key, key_len);
    msgpack_pack_str(pk, val_len);
    msgpack_pack_str_body(pk, val, val_len);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s /path/to/libraw_msgpack_api.so\n", argv[0]);
        fprintf(stderr, "Example: ./build/bin/test_raw_msgpack_api ./build/lib/libraw_msgpack_api.so\n");
        return 1;
    }
    const char *lib_path = argv[1];

    void *handle = dlopen(lib_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Failed to open libraw_msgpack_api.so: %s\n", dlerror());
        return 1;
    }

    init_t init = (init_t)dlsym(handle, "init");
    if (!init) {
        fprintf(stderr, "Failed to find init: %s\n", dlerror());
        return 1;
    }

    add_data_t add_data = (add_data_t)dlsym(handle, "add_data");
    if (!add_data) {
        fprintf(stderr, "Failed to find add_data: %s\n", dlerror());
        return 1;
    }

    finalize_t finalize = (finalize_t)dlsym(handle, "finalize");
    if (!finalize) {
        fprintf(stderr, "Failed to find finalize: %s\n", dlerror());
        return 1;
    }

    // ==================================================================================
    fluentbit_export_parameters_t params;
    params.num_params = 1;
    params.params = (fluentbit_param_pair_t*)calloc(1, sizeof(fluentbit_param_pair_t));
    params.params[0].name = "tag_match_pair";
    params.params[0].val = "ufm_telemetry";


    void *raw_msgpack_api_ctx_ = init("forward", "127.0.0.1", "24224", &params, "test_in_raw_api");
    if (!raw_msgpack_api_ctx_) {
        fprintf(stderr, "Failed to initialize msgpack_packer\n");
        return 1;
    }

    // ==================================================================================


    for (int i = 2; i < 10; i++) {
        msgpack_sbuffer sbuf;
        msgpack_sbuffer_init(&sbuf);

        /* serialize values into the buffer using msgpack_sbuffer_write callback function. */
        msgpack_packer pk;
        msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

        uint64_t timestamp = 11111 * i;
        fprintf(stdout, "timestamp: %lu\n", timestamp);

        msgpack_pack_array(&pk, 2); // 2 elements in the array
        // msgpack_pack_array(&pk, 2); // 2 elements in the array
        msgpack_pack_double(&pk, (double)timestamp); // first element is double
        // msgpack_pack_map(&pk, 0); // second is a map with 3 elements

        msgpack_pack_map(&pk, 3); // second is a map with 3 elements
        pack_key_val_str(&pk, "type", 4, "counters", 8);
        pack_key_val_str(&pk, "source", 6, "test_source", 11);
        pack_key_val_uint64(&pk, "timestamp", 9, timestamp);

        fprintf(stdout, "send buffer: %d\n", i);
        add_data(raw_msgpack_api_ctx_, (void *)sbuf.data, sbuf.size);
        msgpack_sbuffer_destroy(&sbuf);
    }


    // ==================================================================================

    finalize(raw_msgpack_api_ctx_);
    dlclose(handle);
    free(params.params);

    fprintf(stdout, "Done\n");
    return 0;
}
