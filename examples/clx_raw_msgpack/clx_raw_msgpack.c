/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit Demo
 *  ===============
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <fluent-bit.h>
#include <sys/socket.h>
#include <sys/un.h>


#define VERBOSE
#define SERVER_SOCK_PATH "./fb_sock_server"
#define CLIENT_SOCK_PATH "./fb_sick_client"


flb_ctx_t *ctx;
struct flb_input_instance *i_ins;
int i;
int n;

flb_ctx_t *ctx;
int in_ffd;
int out_ffd;

int doorbell_cli;
char buffer[8192 * 2]; // 16 kb

typedef struct doorbell_msg_t {
    int data_len;
} doorbell_msg_t;


#if 1
#include <stdio.h>

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}
#endif


int ipc_unix_sock_cli_create(char *sock_path) {
    int socket_fd;
    struct sockaddr_un client_address;

    if ((socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
        printf("Failed to create client unix sock\n");
        return -1;
    }
#ifdef VERBOSE
    printf("Creating Unix Domain socket: %s,  socket=%d\n", sock_path, socket_fd);
#endif
    memset(&client_address, 0, sizeof(struct sockaddr_un));
    client_address.sun_family = AF_UNIX;
    strcpy(client_address.sun_path, sock_path);
    // strcpy(client_address.sun_path, "./UDSDGCLNT");

    unlink(sock_path);
    if (bind(socket_fd, (const struct sockaddr *) &client_address, sizeof(struct sockaddr_un)) < 0) {
        close(socket_fd);
        printf("Failed to bind client unix sock\n");
        return -1;
    }
    return socket_fd;
}


bool ring_doorbell(int client_fd, int data_len) {
    doorbell_msg_t ring_msg;
    ring_msg.data_len = data_len;
    int msg_len = sizeof(ring_msg);

    socklen_t address_length = sizeof(struct sockaddr_un);
    struct sockaddr_un server_address;

    int bytes_sent;
    int bytes_received;

    memset(&server_address, 0, address_length);
    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, SERVER_SOCK_PATH);

    // TBD(romanpr): to put timeout on socket
    bytes_sent     = sendto(client_fd,
                            (char *) &ring_msg, msg_len,
                            0, (struct sockaddr *) &server_address,
                            address_length);
    // printf("bytes_sent = %d \n", bytes_sent);

    bytes_received = recvfrom(client_fd,
                              (char *) &ring_msg, msg_len,
                              0, (struct sockaddr *) &(server_address),
                              &address_length);
    if (bytes_received != msg_len) {
        // printf("bytes_received: wrong size datagram\n");
        return false;
    }

    return true;
}


int init() {
#ifdef VERBOSE
    printf("hello-word-init\n");
#endif

    /* Initialize library */
    ctx = flb_create();
#ifdef VERBOSE
    printf("ctx = %p\n", ctx);
#endif
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    flb_service_set(ctx, "Flush", "0.1", NULL); // to set flush timeout
    flb_service_set(ctx, "Grace", "1", NULL);   // to set timeout before exit
    // flb_service_set(ctx, "FLB_INPUT_CHUNK_FS_MAX_SIZE",   "262", NULL);   // is this thing works?

    // in_ffd = flb_input(ctx, "lib", NULL);
    // in_ffd = flb_input(ctx, "shared_mem_ipc", NULL);
    // flb_input_set(ctx, i_ins->id, "tag", "test", NULL);


    // create a client socket here to be ready to ring to "doorbell"
    doorbell_cli = ipc_unix_sock_cli_create(CLIENT_SOCK_PATH);
#ifdef VERBOSE
    printf ("created client sock %d\n", doorbell_cli);
#endif
    // code from flb_lib.c  flb_input
    char * buffer_ptr = buffer;
    i_ins = flb_input_new(ctx->config, "raw_msgpack", (void *) buffer_ptr, FLB_TRUE);
#ifdef VERBOSE
    printf("i_ins = %p\n", i_ins);
    printf ("i_ins->data = %p\n", i_ins->data);
#endif
    if (!i_ins) {
        return -1;
    }

    // flb_input_set(ctx, i_ins->id, "tag", "test", NULL);
    // out_ffd = flb_output(ctx, "forward", NULL);
    out_ffd = flb_output(ctx, "forward", NULL);
#ifdef VERBOSE
    printf("out_ffd = %d\n", out_ffd);
#endif
    // flb_output_set(ctx, out_ffd, "match", "test", NULL);

    /* Start the background worker */
    flb_start(ctx);
#ifdef VERBOSE
    printf ("init finished\n\n");
#endif
    return 0;
}


int add_data(void* data, int len) {
    if (len == 0)
        return 0;
#ifdef VERBOSE
    // printf("hello-word-add_data\n");
#endif
    // printf ("Append raw data of len %d:\n", len);
    // DumpHex(data, len);
    memcpy(buffer, data, len);
#ifdef VERBOSE
    //printf ("ring the doorbell\n");
#endif
   ring_doorbell(doorbell_cli, len);

    return 0;
}

int finalize() {
#ifdef VERBOSE
    printf("hello-word-exit\n");
#endif
    close(doorbell_cli);
    flb_stop(ctx);
    /* Release Resources */
    flb_destroy(ctx);

    return 0;
}



msgpack_sbuffer generate_message_pack(n)
{
    msgpack_sbuffer sbuf;
    msgpack_sbuffer_init(&sbuf);

    /* serialize values into the buffer using msgpack_sbuffer_write callback function. */
    msgpack_packer pk;
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    // pack array what will contain (n+2) values(ints/booleans/strings)
    msgpack_pack_array(&pk, n + 2);

    int i;
    for (i = 0; i < n; i++)
        msgpack_pack_int(&pk, i);

    // pack the boolean
    msgpack_pack_true(&pk);

    // pack string (size and body)
    msgpack_pack_str(&pk, 11);
    msgpack_pack_str_body(&pk, "test_plugin", 11);

    return sbuf;
}

void dump_packed_message(msgpack_sbuffer sbuf, FILE *out) {
    /* deserialize the buffer into msgpack_object instance. */
    /* deserialized object is valid during the msgpack_zone instance alive. */
    msgpack_zone mempool;
    msgpack_zone_init(&mempool, 2048);

    msgpack_object deserialized;
    msgpack_unpack(sbuf.data, sbuf.size, NULL, &mempool, &deserialized);

    /* print the deserialized object. */
    msgpack_object_print(out, deserialized);
    puts("");

    msgpack_zone_destroy(&mempool);
}

int main()
{
    return 0;
}


int old_main()
{
    int i;
    int n;
    char tmp[256];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Initialize library */
    ctx = flb_create();
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    // Set Service Properties
    int ret = flb_service_set(ctx, "Flush", "1", NULL);

    // Enable Input Plugin Instance
    in_ffd = flb_input(ctx, "lib", NULL);
    // Set Input Plugin Properties
    // user can input more pais tag1: test1, tag2:test2 ...
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, "stdout", NULL);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    /* Start the background worker */
    flb_start(ctx);

    for (i = 0; i < 10; i++) {
        msgpack_sbuffer m_p = generate_message_pack(i);
        dump_packed_message(m_p, stdout);

        msgpack_sbuffer_destroy(&m_p);
    }

    flb_stop(ctx);

    /* Release Resources */
    flb_destroy(ctx);

    return 0;
}
