#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "websocket-server/websocket.h"

typedef struct {
  uint8_t *last_data;
  size_t last_len;
  size_t send_count;
  size_t close_count;
  bool closed;
} transport_probe_t;

typedef struct {
  size_t on_open_calls;
  size_t on_message_calls;
  size_t on_close_calls;
  ws_opcode_t last_opcode;
  uint8_t last_payload[256];
  size_t last_payload_len;
} callback_probe_t;

typedef struct {
  ws_conn_t *conn;
  transport_probe_t transport;
  callback_probe_t callbacks;
} test_fixture_t;

static bool g_failed = false;

static void fail_check(const char *expr, const char *file, int line) {
  fprintf(stderr, "[FAIL] %s at %s:%d\n", expr, file, line);
  g_failed = true;
}

#define CHECK(expr)                                                            \
  do {                                                                         \
    if (!(expr)) {                                                             \
      fail_check(#expr, __FILE__, __LINE__);                                   \
      return;                                                                  \
    }                                                                          \
  } while (false)

static void probe_clear_last_send(transport_probe_t *probe) {
  free(probe->last_data);
  probe->last_data = nullptr;
  probe->last_len = 0U;
}

static void probe_send_raw(ws_transport_t *self, const uint8_t *data,
                           size_t len) {
  auto probe = (transport_probe_t *)self->user_data;
  probe->send_count += 1U;

  probe_clear_last_send(probe);

  auto copy = (uint8_t *)calloc(len + 1U, sizeof(uint8_t));
  if (copy == nullptr) {
    return;
  }
  if (len > 0U) {
    memcpy(copy, data, len);
  }
  probe->last_data = copy;
  probe->last_len = len;
}

static void probe_close(ws_transport_t *self) {
  auto probe = (transport_probe_t *)self->user_data;
  probe->close_count += 1U;
  probe->closed = true;
}

static void cb_on_open(ws_conn_t *conn) {
  auto probe = (callback_probe_t *)ws_conn_get_context(conn);
  probe->on_open_calls += 1U;
}

static void cb_on_message(ws_conn_t *conn, const uint8_t *data, size_t len,
                          ws_opcode_t opcode) {
  auto probe = (callback_probe_t *)ws_conn_get_context(conn);
  probe->on_message_calls += 1U;
  probe->last_opcode = opcode;
  probe->last_payload_len =
      len > sizeof(probe->last_payload) ? sizeof(probe->last_payload) : len;
  if (probe->last_payload_len > 0U) {
    memcpy(probe->last_payload, data, probe->last_payload_len);
  }
}

static void cb_on_close(ws_conn_t *conn) {
  auto probe = (callback_probe_t *)ws_conn_get_context(conn);
  probe->on_close_calls += 1U;
}

[[nodiscard]]
static bool fixture_init(test_fixture_t *fixture) {
  memset(fixture, 0, sizeof(*fixture));

  ws_transport_t transport = {.user_data = &fixture->transport,
                              .send_raw = probe_send_raw,
                              .close = probe_close};

  ws_callbacks_t callbacks = {.on_open = cb_on_open,
                              .on_message = cb_on_message,
                              .on_close = cb_on_close};

  fixture->conn = ws_conn_new(transport, callbacks, &fixture->callbacks);
  return fixture->conn != nullptr;
}

static void fixture_deinit(test_fixture_t *fixture) {
  ws_conn_free(fixture->conn);
  fixture->conn = nullptr;
  probe_clear_last_send(&fixture->transport);
}

static void do_handshake(test_fixture_t *fixture) {
  static constexpr char request[] =
      "GET /chat HTTP/1.1\r\n"
      "Host: server.example.com\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
      "Sec-WebSocket-Version: 13\r\n"
      "\r\n";

  ws_conn_feed(fixture->conn, (const uint8_t *)request, sizeof(request) - 1U);
}

static void test_handshake_success_sends_accept() {
  test_fixture_t fixture;
  CHECK(fixture_init(&fixture));
  do_handshake(&fixture);

  CHECK(fixture.callbacks.on_open_calls == 1U);
  CHECK(fixture.transport.send_count == 1U);
  CHECK(fixture.transport.last_data != nullptr);
  CHECK(strstr((const char *)fixture.transport.last_data,
               "HTTP/1.1 101 Switching Protocols") != nullptr);
  CHECK(strstr((const char *)fixture.transport.last_data,
               "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") !=
        nullptr);

  fixture_deinit(&fixture);
}

static void test_handshake_failure_returns_http_400_and_closes() {
  test_fixture_t fixture;
  CHECK(fixture_init(&fixture));

  static constexpr char bad_request[] = "GET / HTTP/1.1\r\n"
                                        "Host: localhost\r\n"
                                        "Upgrade: websocket\r\n"
                                        "Connection: Upgrade\r\n"
                                        "Sec-WebSocket-Version: 13\r\n"
                                        "\r\n";

  ws_conn_feed(fixture.conn, (const uint8_t *)bad_request,
               sizeof(bad_request) - 1U);

  CHECK(fixture.callbacks.on_open_calls == 0U);
  CHECK(fixture.transport.send_count >= 1U);
  CHECK(fixture.transport.last_data != nullptr);
  CHECK(strstr((const char *)fixture.transport.last_data, "400 Bad Request") !=
        nullptr);
  CHECK(fixture.transport.closed);
  CHECK(fixture.transport.close_count >= 1U);

  fixture_deinit(&fixture);
}

static void build_masked_client_frame(ws_opcode_t opcode, const uint8_t *data,
                                      size_t len, uint8_t *out,
                                      size_t *out_len) {
  static constexpr uint8_t mask[4] = {0x37U, 0xFAU, 0x21U, 0x3DU};
  out[0] = (uint8_t)(0x80U | (uint8_t)opcode);
  out[1] = (uint8_t)(0x80U | (uint8_t)len);
  memcpy(out + 2U, mask, sizeof(mask));
  for (size_t i = 0U; i < len; ++i) {
    out[6U + i] = (uint8_t)(data[i] ^ mask[i % 4U]);
  }
  *out_len = 6U + len;
}

static void test_text_frame_dispatches_message_callback() {
  test_fixture_t fixture;
  CHECK(fixture_init(&fixture));
  do_handshake(&fixture);

  uint8_t frame[64];
  size_t frame_len = 0U;
  static constexpr uint8_t payload[] = {'h', 'e', 'l', 'l', 'o'};
  build_masked_client_frame(WS_OP_TEXT, payload, sizeof(payload), frame,
                            &frame_len);
  ws_conn_feed(fixture.conn, frame, frame_len);

  CHECK(fixture.callbacks.on_message_calls == 1U);
  CHECK(fixture.callbacks.last_opcode == WS_OP_TEXT);
  CHECK(fixture.callbacks.last_payload_len == sizeof(payload));
  CHECK(memcmp(fixture.callbacks.last_payload, payload, sizeof(payload)) == 0);

  fixture_deinit(&fixture);
}

static void test_ping_generates_pong_frame() {
  test_fixture_t fixture;
  CHECK(fixture_init(&fixture));
  do_handshake(&fixture);
  probe_clear_last_send(&fixture.transport);

  uint8_t frame[64];
  size_t frame_len = 0U;
  static constexpr uint8_t payload[] = {'O', 'K'};
  build_masked_client_frame(WS_OP_PING, payload, sizeof(payload), frame,
                            &frame_len);
  ws_conn_feed(fixture.conn, frame, frame_len);

  CHECK(fixture.transport.last_data != nullptr);
  CHECK(fixture.transport.last_len == sizeof(payload) + 2U);
  CHECK(fixture.transport.last_data[0] == 0x8AU);
  CHECK(fixture.transport.last_data[1] == sizeof(payload));
  CHECK(memcmp(fixture.transport.last_data + 2U, payload, sizeof(payload)) ==
        0);

  fixture_deinit(&fixture);
}

static void test_server_send_text_frame() {
  test_fixture_t fixture;
  CHECK(fixture_init(&fixture));
  do_handshake(&fixture);
  probe_clear_last_send(&fixture.transport);

  static constexpr uint8_t payload[] = {'y', 'o'};
  ws_conn_send(fixture.conn, payload, sizeof(payload), WS_OP_TEXT);

  CHECK(fixture.transport.last_data != nullptr);
  CHECK(fixture.transport.last_len == sizeof(payload) + 2U);
  CHECK(fixture.transport.last_data[0] == 0x81U);
  CHECK(fixture.transport.last_data[1] == sizeof(payload));
  CHECK(memcmp(fixture.transport.last_data + 2U, payload, sizeof(payload)) ==
        0);

  fixture_deinit(&fixture);
}

int main() {
  test_handshake_success_sends_accept();
  test_handshake_failure_returns_http_400_and_closes();
  test_text_frame_dispatches_message_callback();
  test_ping_generates_pong_frame();
  test_server_send_text_frame();

  if (g_failed) {
    return EXIT_FAILURE;
  }
  printf("All unit tests passed.\n");
  return EXIT_SUCCESS;
}
