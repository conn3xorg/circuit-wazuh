#!/usr/bin/env python3
"""A TLS listener that notes how many bytes each connection sent, never what they were."""
import socket
import ssl
import sys

tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(sys.argv[2], sys.argv[3])
server = socket.create_server(("127.0.0.1", int(sys.argv[1])))
while True:
    conn, _ = server.accept()
    try:
        with tls.wrap_socket(conn, server_side=True) as t:
            with open(sys.argv[4], "a") as log:
                print(len(t.recv(65536)), file=log)
    except OSError:
        pass
