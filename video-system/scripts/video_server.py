#!/usr/bin/env python3

import http.server
import socketserver
import os

PORT = 10001  # Using port 10001 (close to webmin's 10000)

class VideoHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        try:
            print(f"Request: {self.path} from {self.client_address}")
            if self.path == '/' or self.path == '/index.html':
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                html = """<!DOCTYPE html>
<html>
<head><title>Video Server</title></head>
<body style="background:#000;color:white;text-align:center;padding:50px;">
    <h1>Video Server Working on Port 10001!</h1>
    <video controls autoplay loop muted style="max-width:80%;">
        <source src="sample_video.mp4" type="video/mp4">
        Video not supported
    </video>
    <p style="color:green;">Port 10001 - Similar range to webmin (10000)</p>
</body>
</html>"""
                self.wfile.write(html.encode())
            else:
                super().do_GET()
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    print(f"Starting server on 0.0.0.0:{PORT}")
    with socketserver.TCPServer(("0.0.0.0", PORT), VideoHandler) as httpd:
        print(f"Server running at http://0.0.0.0:{PORT}")
        httpd.serve_forever()