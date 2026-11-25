#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""矩阵测试用本地 HTTP 探测目标：/generate_204 → 204，其余路径 → 200。
用法: python3 echo_204.py [端口]   # 默认 18999
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18999


class ThreadedServer(ThreadingHTTPServer):
    allow_reuse_address = True
    request_queue_size = 128
    daemon_threads = True


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        code = 204 if self.path.startswith("/generate_204") else 200
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = do_HEAD = do_GET

    def log_message(self, *args):  # 静默访问日志
        pass


if __name__ == "__main__":
    ThreadedServer(("127.0.0.1", PORT), H).serve_forever()
