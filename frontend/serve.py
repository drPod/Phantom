#!/usr/bin/env python3
import http.server, socketserver
PORT = 8080
with socketserver.TCPServer(('', PORT), http.server.SimpleHTTPRequestHandler) as httpd:
    print(f'Serving on http://localhost:{PORT}')
    httpd.serve_forever()
