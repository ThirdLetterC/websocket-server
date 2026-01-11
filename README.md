# WebSocket Server (C23 + libuv)

Minimal WebSocket server skeleton written in strict C23 with a libuv transport layer and built with Zig. The code separates protocol handling from the event loop via a small transport interface and exposes simple application callbacks for `on_open`, `on_message`, and `on_close`.

## Status and Limitations
- Protocol handling is a stub: there is no HTTP handshake, no masking validation, and no WebSocket frame parsing. Incoming bytes are delivered directly to the `on_message` callback, and `ws_conn_send` writes raw bytes back.
- Suitable as a starting point for experimenting with libuv and C23 patterns, not for production use.
- No TLS or authentication; connections are plain TCP.

## Prerequisites
- Zig (for the build system) and a C toolchain that supports `-std=c23`.
- libuv headers and libraries (e.g., `sudo apt install libuv1-dev` or `brew install libuv`).
- Optional tools: `just` for task shortcuts, `clang-format` for formatting, `valgrind` for leak checks, and `wscat`/`k6` for quick client tests.

## Building
- Default debug build: `just build` or `zig build`.
- Release-style builds: `zig build -Doptimize=ReleaseSafe` (or `ReleaseFast`/`ReleaseSmall`).
- Address/UB/leak sanitizers (Debug only): `zig build -Dsanitizers=true`.

## Running
- Start the server on the default port 8080: `just run` or `zig build run`.
- Choose a port: `zig build run -- 9090` or `just run p=9090`.
- Shutdown signals: SIGINT/SIGTERM trigger a graceful loop stop.
- The server emits a console log on new connections and echoes raw data back.

## Testing (lightweight)
- Manual byte echo with `wscat` or similar tools may fail because the WebSocket handshake is not implemented. For now, you can connect with a raw TCP client (e.g., `nc localhost 8080`) and observe echoed bytes.
- A simple k6 script (`test/ws_test.js`) is included as a placeholder load test once proper WebSocket framing is added.

## Project Layout
- `src/main.c` — wires CLI args, signal handling, and application callbacks.
- `src/server.c` — libuv server setup, connection lifecycle, and transport glue.
- `src/websocket.c` / `src/websocket.h` — protocol stubs and callback surfaces.
- `build.zig` — Zig build graph, compiler flags (`-std=c23 -Wall -Wextra -Wpedantic -Werror`), and sanitizer toggles.
- `justfile` — helper tasks for build, run, deps, format, and leak checks.
