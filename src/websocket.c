#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "websocket.h"

struct ws_conn_s {
    ws_transport_t transport;
    ws_callbacks_t callbacks;
    void *user_context;
};

[[nodiscard]]
ws_conn_t* ws_conn_new(ws_transport_t transport, ws_callbacks_t callbacks, void *external_context) {
    auto *conn = (ws_conn_t *)calloc(1, sizeof(ws_conn_t));
    if (conn == nullptr) {
        return nullptr;
    }

    conn->transport = transport;
    conn->callbacks = callbacks;
    conn->user_context = external_context;

    if (conn->callbacks.on_open != nullptr) {
        conn->callbacks.on_open(conn);
    }

    return conn;
}

void ws_conn_free(ws_conn_t *conn) {
    if (conn == nullptr) {
        return;
    }

    if (conn->callbacks.on_close != nullptr) {
        conn->callbacks.on_close(conn);
    }

    free(conn);
}

void ws_conn_feed(ws_conn_t *conn, const uint8_t *data, size_t len) {
    if (conn == nullptr || data == nullptr || len == 0U) {
        return;
    }

    if (conn->callbacks.on_message != nullptr) {
        conn->callbacks.on_message(conn, data, len, WS_OP_BINARY);
    }
}

void ws_conn_send(ws_conn_t *conn, const uint8_t *data, size_t len, ws_opcode_t opcode) {
    (void)opcode;
    if (conn == nullptr || data == nullptr || len == 0U) {
        return;
    }
    if (conn->transport.send_raw != nullptr) {
        conn->transport.send_raw(&conn->transport, data, len);
    }
}

void* ws_conn_get_context(ws_conn_t *conn) {
    if (conn == nullptr) {
        return nullptr;
    }
    return conn->user_context;
}
