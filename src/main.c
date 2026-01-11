#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "websocket.h"

/**
 * @brief Application-level callback triggered when a WebSocket handshake completes.
 */
void my_on_open(ws_conn_t *conn) {
    printf("[Server] New WebSocket connection opened.\n");
    
    const char *welcome = "Welcome to the C WebSocket Echo Server!";
    ws_conn_send(conn, (const uint8_t*)welcome, strlen(welcome), WS_OP_TEXT);
}

/**
 * @brief Application-level callback triggered when a message is received.
 * Logic: Echoes the message back to the client with a prefix.
 */
void my_on_message(ws_conn_t *conn, const uint8_t *data, size_t len, ws_opcode_t opcode) {
    // Print the received message (assuming TEXT for this simple demo)
    if (opcode == WS_OP_TEXT) {
        printf("[Server] Received: %.*s\n", (int)len, (const char*)data);
    } else {
        printf("[Server] Received binary data of length: %zu\n", len);
    }

    // Echo logic: Send the exact same data back
    ws_conn_send(conn, data, len, opcode);
}

/**
 * @brief Application-level callback triggered when the connection is closed.
 */
void my_on_close(ws_conn_t *conn) {
    printf("[Server] WebSocket connection closed.\n");
}

int main(int argc, char **argv) {
    int port = 8080;
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    // 1. Define application callbacks
    ws_callbacks_t callbacks = {
        .on_open = my_on_open,
        .on_message = my_on_message,
        .on_close = my_on_close
    };

    /**
     * NOTE: In a full implementation, you would pass these callbacks 
     * into the server initialization. Here, we assume the server 
     * start logic (provided in the previous turn) uses these.
     */
    printf("Starting WebSocket Echo Server on port %d...\n", port);
    
    // External function from the libuv_ws_server implementation
    // This function initializes libuv, binds the socket, and handles the loop.
    // void start_ws_server(int port, ws_callbacks_t callbacks);
    
    // For this demonstration, we call the placeholder start function
    // start_ws_server(port, callbacks);

    return 0;
}
