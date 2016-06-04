#!/usr/bin/env python3
#
# 0. Resolve the domain name "example.com" to an IP address
# 1. Execute this Python script on a machine with the IP address
# 2. Open https://example.com:4433/ in a web browser
#

import http.server
import json
import os
import lightu2f

tokens = []
req = None

DIR = os.path.dirname(os.path.abspath(__file__))
APPLICATION_IDENTITY = 'https://example.com:4433'

class MyWebServer(http.server.BaseHTTPRequestHandler):

    def get_request_body(self):
        return self.rfile.read(int(self.headers['Content-Length'])).decode()

    def respond_200(self, data):
        self.send_response(200)
        self.end_headers()
        if type(data) is bytes:
            self.wfile.write(data)
        elif type(data) is str:
            self.wfile.write(data.encode())
        else:
            raise TypeError

    def do_GET(self):
        path = self.path
        if path == '/':
            self.send_response(200)
            self.end_headers()
            with open(DIR + '/index.html', 'rb') as f:
                self.wfile.write(f.read())
        elif path == '/u2f-api.js':
            self.send_response(200)
            self.end_headers()
            with open(DIR + '/u2f-api.js', 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        global req
        if self.path == '/u2f_register':
            req = lightu2f.create_registration_request(tokens)
            self.respond_200(req)
        elif self.path == '/u2f_register_finish':
            res = self.get_request_body()
            token, _, _ = lightu2f.handle_registration_response(req, res)
            tokens.append(token)
            self.respond_200(
                    'registered new U2F security key: {}'.format(token.hex()))
        elif self.path == '/u2f_authenticate':
            req = lightu2f.create_authentication_request(tokens)
            self.respond_200(req)
        elif self.path == '/u2f_authenticate_finish':
            res = self.get_request_body()
            token, _, _ = lightu2f.handle_authentication_response(
                                                    tokens, req, res)
            self.respond_200(
                    'authenticated with the U2F security key: {}'.format(
                                                    token.hex()))

def ssl_wrap(sock):
    import ssl
    path_to_my_self_signed_cert = DIR + '/webserver-credentials.pem'
    return ssl.wrap_socket(sock, certfile=path_to_my_self_signed_cert)

def main():
    lightu2f.set_application_identity(APPLICATION_IDENTITY)
    webserver = http.server.HTTPServer(('', 4433), MyWebServer)
    webserver.socket = ssl_wrap(webserver.socket)
    webserver.serve_forever()

if __name__ == '__main__':
    main()
