#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <uv.h>

#include "websocket.h"
#include "server.h"

constexpr size_t READ_CHUNK = 4'096;

typedef struct {
    uv_write_t req;
    uint8_t *buffer;
} write_ctx_t;

/**
 * @brief Internal wrapper linking the protocol and libuv handle.
 */
typedef struct {
    uv_tcp_t tcp;
    ws_conn_t *ws;
    ws_transport_t transport;
} client_ctx_t;

static ws_callbacks_t g_callbacks;

void server_set_callbacks(ws_callbacks_t callbacks) {
    g_callbacks = callbacks;
}

ws_callbacks_t server_get_callbacks() {
    return g_callbacks;
}

static void on_uv_write(uv_write_t *req, int status) {
    (void)status;
    auto *ctx = (write_ctx_t *)req;
    free(ctx->buffer);
    free(ctx);
}

static void transport_send_raw(ws_transport_t *self, const uint8_t *data, size_t len) {
    auto *ctx = (client_ctx_t *)self->user_data;

    auto *write_ctx = (write_ctx_t *)calloc(1, sizeof(write_ctx_t));
    if (write_ctx == nullptr) {
        return;
    }

    write_ctx->buffer = (uint8_t *)calloc(len, sizeof(uint8_t));
    if (write_ctx->buffer == nullptr) {
        free(write_ctx);
        return;
    }

    memcpy(write_ctx->buffer, data, len);

    uv_buf_t buf = uv_buf_init((char *)write_ctx->buffer, (unsigned int)len);
    uv_write(&write_ctx->req, (uv_stream_t *)&ctx->tcp, &buf, 1, on_uv_write);
}

static void on_uv_client_closed(uv_handle_t *handle) {
    auto *ctx = (client_ctx_t *)handle->data;
    ws_conn_free(ctx->ws);
    free(ctx);
}

static void transport_close(ws_transport_t *self) {
    auto *ctx = (client_ctx_t *)self->user_data;
    uv_close((uv_handle_t *)&ctx->tcp, on_uv_client_closed);
}

static void on_uv_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)suggested_size;
    (void)handle;
    buf->base = (char *)calloc(READ_CHUNK, sizeof(uint8_t));
    buf->len = buf->base == nullptr ? 0U : (unsigned int)READ_CHUNK;
}

static void on_uv_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    auto *ctx = (client_ctx_t *)stream->data;
    if (nread > 0) {
        ws_conn_feed(ctx->ws, (uint8_t *)buf->base, (size_t)nread);
    } else if (nread < 0) {
        ctx->transport.close(&ctx->transport);
    }
    free(buf->base);
}

static void on_new_connection(uv_stream_t *server, int status) {
    if (status < 0) {
        return;
    }

    auto *ctx = (client_ctx_t *)calloc(1, sizeof(client_ctx_t));
    if (ctx == nullptr) {
        return;
    }

    uv_tcp_init(server->loop, &ctx->tcp);
    ctx->tcp.data = ctx;

    if (uv_accept(server, (uv_stream_t *)&ctx->tcp) == 0) {
        ctx->transport.user_data = ctx;
        ctx->transport.send_raw = transport_send_raw;
        ctx->transport.close = transport_close;

        ctx->ws = ws_conn_new(ctx->transport, server_get_callbacks(), nullptr);
        if (ctx->ws == nullptr) {
            transport_close(&ctx->transport);
            return;
        }

        uv_read_start((uv_stream_t *)&ctx->tcp, on_uv_alloc, on_uv_read);
    } else {
        free(ctx);
    }
}

void start_ws_server(int port, ws_callbacks_t callbacks) {
    server_set_callbacks(callbacks);
    auto *loop = uv_default_loop();
    uv_tcp_t server;
    uv_tcp_init(loop, &server);

    struct sockaddr_in addr;
    uv_ip4_addr("0.0.0.0", port, &addr);
    uv_tcp_bind(&server, (const struct sockaddr *)&addr, 0);
    uv_listen((uv_stream_t *)&server, 128, on_new_connection);
    uv_run(loop, UV_RUN_DEFAULT);
}
