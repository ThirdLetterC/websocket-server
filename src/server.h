#ifndef SERVER_H
#define SERVER_H

#include "websocket.h"

void server_set_callbacks(ws_callbacks_t callbacks);
ws_callbacks_t server_get_callbacks();
void start_ws_server(int port, ws_callbacks_t callbacks);

#endif // SERVER_H
