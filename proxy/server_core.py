import socket
import sys
import ssl
from http.server import HTTPServer
from socketserver import ThreadingMixIn
from request_handler import ProxyInterceptor

class MultiThreadedProxyServer(ThreadingMixIn, HTTPServer):
    def handle_error(self, request, client_address):
        error_class, error = sys.exc_info()[:2]
        if error_class is socket.error or error_class is ssl.SSLError:
            pass
        else:
            try:
                return HTTPServer.handle_error(self, request, client_address)
            except Exception as e:
                print(f"Unexpected error in handle_error: {e}")               
        
def run_proxy_server(config):
    protocol = "HTTP/1.1"
    server_address = (config.bind_address, config.port)
    ProxyInterceptor.protocol_version = protocol
    proxy_server = MultiThreadedProxyServer(server_address, ProxyInterceptor)
    server_info = proxy_server.socket.getsockname()
    print(f"Proxy server running on {server_info[0]}:{server_info[1]} ...")
    proxy_server.serve_forever()