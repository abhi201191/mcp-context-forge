from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

received_code = None

class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global received_code
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        if "code" in qs:
            received_code = qs["code"][0]
            msg = "<h1>Authentication successful! You may close this window.</h1>"
        else:
            msg = "<h1>No authorization code found.</h1>"

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(msg.encode())

def run_callback_server():
    server = HTTPServer(("localhost", 8000), CallbackHandler)
    print("Callback server running at http://localhost:8000")
    server.handle_request()
    return received_code