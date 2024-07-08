import gzip
import http.client
import re
import select
import socket
import ssl
import threading
import urllib.parse
import zlib
import os
import time
import json
import mysql.connector
import http.cookies
import traceback
import logging
from subprocess import Popen, PIPE
from http.server import BaseHTTPRequestHandler
from http.client import HTTPMessage
from utils import colorize, parse_query_string, log_request_info
from settings import config, pre_request_hook, post_response_hook, logging_hook, db_settings

# 로깅 설정
logging.basicConfig(filename='proxy_server.log', level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ProxyInterceptor(BaseHTTPRequestHandler):
    mutex = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.connection_pool = threading.local()
        self.connection_pool.connections = {}
        self.tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.tls_context.check_hostname = False
        self.tls_context.verify_mode = ssl.CERT_NONE
        super().__init__(*args, **kwargs)

    def log_error(self, format, *args):
        if isinstance(args[0], socket.timeout):
            return
        logger.error(format % args)

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            logger.debug(traceback.format_exc())
            self.close_connection = True

    def parse_request(self):
        try:
            return super().parse_request()
        except Exception as e:
            logger.error(f"Error parsing request: {e}")
            logger.debug(traceback.format_exc())
            self.close_connection = True
            return False

    def do_CONNECT(self):
        host, _ = self.path.split(":", 1)
        if self.should_intercept(host):
            logger.info(f"Intercepting HTTPS connection for: {host}")
            self.intercept_ssl()
        else:
            logger.info(f"Relaying HTTPS connection for: {host}")
            self.relay_ssl()

    def should_intercept(self, host):
        return (os.path.isfile(config.ca_key) and
                os.path.isfile(config.ca_cert) and
                os.path.isfile(config.cert_key) and
                os.path.isdir(config.cert_dir) and
                (config.intercept_domain == "*" or config.intercept_domain == host))

    def intercept_ssl(self):
        hostname = self.path.split(":")[0]
        cert_path = os.path.join(config.cert_dir, f"{hostname}.pem")
        conf_path = os.path.join(config.cert_dir, f"{hostname}.conf")

        logger.info(f"Intercepting SSL for hostname: {hostname}")
        logger.debug(f"Certificate path: {cert_path}")
        logger.debug(f"Config path: {conf_path}")

        with self.mutex:
            if not os.path.isfile(cert_path):
                logger.info(f"Certificate not found, generating new one for {hostname}")
                if not self.generate_cert(hostname, cert_path, conf_path):
                    self.send_error(500, "Failed to generate certificate")
                    return

        self.send_response(200, "Connection Established")
        self.end_headers()

        try:
            self.tls_context.load_cert_chain(certfile=cert_path, keyfile=config.cert_key)
        except Exception as e:
            logger.error(f"Error loading certificate for {hostname}: {e}")
            return

        try:
            self.connection = self.tls_context.wrap_socket(self.connection, server_side=True)
            logger.info(f"SSL interception successful for {hostname}")
        except ssl.SSLError as e:
            logger.error(f"SSL 오류 for {hostname}: {e}")
            return
        except Exception as e:
            logger.error(f"예상치 못한 오류 for {hostname}: {e}")
            return

        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conn_type = self.headers.get("Proxy-Connection", "")
        self.close_connection = (self.protocol_version != "HTTP/1.1" or conn_type.lower() == "close")

        logger.info(f"SSL interception completed for {hostname}")

    def generate_cert(self, hostname, cert_path, conf_path):
        category = "IP" if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) else "DNS"
        with open(conf_path, "w") as f:
            f.write(f"subjectAltName={category}:{hostname}\nextendedKeyUsage=serverAuth\n")
        epoch = str(int(time.time() * 1000))
        
        logger.info(f"Generating certificate for {hostname}")
        logger.debug(f"Certificate path: {cert_path}")
        logger.debug(f"Config path: {conf_path}")
        
        # CSR 생성
        csr_command = [
            "openssl", "req", "-new", "-key", config.cert_key,
            "-subj", f"/CN={hostname}"
        ]
        logger.debug(f"CSR command: {' '.join(csr_command)}")
        csr_process = Popen(csr_command, stdout=PIPE, stderr=PIPE)
        csr, err = csr_process.communicate()
        if csr_process.returncode != 0:
            logger.error(f"CSR 생성 오류: {err.decode()}")
            return False
        
        # 인증서 서명
        cert_command = [
            "openssl", "x509", "-req", "-days", "365", "-CA", config.ca_cert,
            "-CAkey", config.ca_key, "-set_serial", epoch, "-out", cert_path,
            "-extfile", conf_path
        ]
        logger.debug(f"Certificate signing command: {' '.join(cert_command)}")
        cert_process = Popen(cert_command, stdin=PIPE, stderr=PIPE)
        _, err = cert_process.communicate(input=csr)
        if cert_process.returncode != 0:
            logger.error(f"인증서 서명 오류: {err.decode()}")
            return False
        
        logger.info(f"Certificate generated successfully for {hostname}")
        return True

    def relay_ssl(self):
        address = self.path.split(":", 1)
        address = (address[0], int(address[1]) or 443)
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            logger.error(f"Error creating connection to {address}: {e}")
            self.send_error(502)
            return
        self.send_response(200, "Connection Established")
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = False
        while not self.close_connection:
            rlist, _, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                try:
                    data = r.recv(8192)
                    if not data:
                        self.close_connection = True
                        break
                    other.sendall(data)
                except Exception as e:
                    logger.error(f"Error in relay_ssl: {e}")
                    self.close_connection = True
                    break

    def do_GET(self):
        self.handle_request("GET")

    do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = do_GET

    def handle_request(self, method):
        logger.info(f"Starting to process {method} request for URL: {self.path}")
        try:
            if self.path == "http://fuzzingzzingi.cert/":
                self.serve_ca_cert()
                return

            req = self
            content_length = int(req.headers.get("Content-Length", 0))
            req_body = self.rfile.read(content_length) if content_length else b""

            if req.path[0] == "/":
                req.path = f"{'https' if isinstance(self.connection, ssl.SSLSocket) else 'http'}://{req.headers['Host']}{req.path}"

            if pre_request_hook:
                modified_body = pre_request_hook(req, req_body.decode())
                if modified_body is False:
                    self.send_error(403)
                    return
                if modified_body is not None:
                    req_body = modified_body.encode()
                    req.headers["Content-Length"] = str(len(req_body))

            url_parts = urllib.parse.urlsplit(req.path)
            scheme, netloc, path = url_parts.scheme, url_parts.netloc, (url_parts.path + "?" + url_parts.query if url_parts.query else url_parts.path)
            assert scheme in ("http", "https")
            if netloc:
                req.headers["Host"] = netloc
            req.headers = self.filter_headers(req.headers)

            origin = (scheme, netloc)
            try:
                if origin not in self.connection_pool.connections:
                    if scheme == "https":
                        self.connection_pool.connections[origin] = http.client.HTTPSConnection(netloc, timeout=self.timeout)
                    else:
                        self.connection_pool.connections[origin] = http.client.HTTPConnection(netloc, timeout=self.timeout)
                conn = self.connection_pool.connections[origin]
                conn.request(method, path, req_body, dict(req.headers))
                res = conn.getresponse()

                if "Content-Length" not in res.headers and "no-store" in res.headers.get("Cache-Control", ""):
                    if post_response_hook:
                        post_response_hook(req, req_body, res, "")
                    res.headers = self.filter_headers(res.headers)
                    self.handle_streaming_response(res)
                    if logging_hook:
                        with self.mutex:
                            logging_hook(req, req_body, res, "")
                    return

                res_body = res.read()
            except Exception as e:
                logger.error(f"Error processing request for {req.path}: {e}")
                logger.debug(traceback.format_exc())
                if origin in self.connection_pool.connections:
                    del self.connection_pool.connections[origin]
                self.send_error(502)
                return

            if post_response_hook:
                content_encoding = res.headers.get("Content-Encoding", "identity")
                decoded_body = self.decompress_content(res_body, content_encoding)
                modified_body = post_response_hook(req, req_body, res, decoded_body)
                if modified_body is False:
                    self.send_error(403)
                    return
                if modified_body is not None:
                    res_body = self.compress_content(modified_body, content_encoding)
                    res.headers["Content-Length"] = str(len(res_body))

            res.headers = self.filter_headers(res.headers)
            content_encoding = res.headers.get("Content-Encoding", "identity")
            decoded_body = self.decompress_content(res_body, content_encoding)

            self.send_response_only(res.status, res.reason)
            for k, v in res.headers.items():
                self.send_header(k, v)
            
            self.send_response_body(res_body)

            if logging_hook:
                with self.mutex:
                    logging_hook(req, req_body, res, decoded_body)
            
            logger.info(f"Attempting to store data for URL: {req.path}")
            self.store_request_data(req, req_body, res, decoded_body)

            logger.info(f"Request processing completed for URL: {req.path}")
        except ssl.SSLError as e:
            logger.error(f"SSL Error occurred: {e}")
        except ConnectionResetError:
            logger.warning("Connection was reset by the client")
        except BrokenPipeError:
            logger.warning("Connection pipe was broken")
        except Exception as e:
            logger.error(f"Unexpected error occurred: {e}")
            logger.debug(traceback.format_exc())
        finally:
            logger.info("Finishing request handling")
            self.finish_request()

    def filter_headers(self, headers: HTTPMessage) -> HTTPMessage:
        hop_by_hop = (
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailers", "transfer-encoding", "upgrade"
        )
        for h in hop_by_hop:
            del headers[h]

        if "Accept-Encoding" in headers:
            ae = headers["Accept-Encoding"]
            filtered_encodings = [x for x in re.split(r",\s*", ae) if x in ("identity", "gzip", "x-gzip", "deflate")]
            headers["Accept-Encoding"] = ", ".join(filtered_encodings)

        return headers

    def compress_content(self, content: bytes, encoding: str) -> bytes:
        if encoding == "identity":
            return content
        elif encoding in ("gzip", "x-gzip"):
            return gzip.compress(content)
        elif encoding == "deflate":
            return zlib.compress(content)
        else:
            raise Exception(f"Unsupported Content-Encoding: {encoding}")

    def decompress_content(self, data: bytes, encoding: str) -> bytes:
        if encoding == "identity":
            return data
        elif encoding in ("gzip", "x-gzip"):
            return gzip.decompress(data)
        elif encoding == "deflate":
            try:
                return zlib.decompress(data)
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception(f"Unsupported Content-Encoding: {encoding}")

    def serve_ca_cert(self):
        logger.info("Serving CA certificate")
        with open(config.ca_cert, "rb") as f:
            cert_data = f.read()

        self.send_response(200, "OK")
        self.send_header("Content-Type", "application/x-x509-ca-cert")
        self.send_header("Content-Length", str(len(cert_data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(cert_data)

    def handle_streaming_response(self, res):
        self.send_response_only(res.status, res.reason)
        for k, v in res.headers.items():
            self.send_header(k, v)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error as e:
            logger.error(f"Socket error in handle_streaming_response: {e}")
        except Exception as e:
            logger.error(f"Error in handle_streaming_response: {e}")

    def store_request_data(self, req, req_body, res, res_body):
        logger.info(f"Entering store_request_data for URL: {req.path}")
        try:
            # 데이터 검증
            if not self.validate_data(req, req_body, res, res_body):
                logger.warning(f"Data validation failed for URL: {req.path}")
                return

            conn = mysql.connector.connect(**db_settings)
            cursor = conn.cursor()

            query = """
            INSERT INTO requests (url, is_https, parameters, method, protocol_version, 
                                headers, cookies, response_status, response_headers, 
                                response_body, ssl_info)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            is_https = isinstance(req.connection, ssl.SSLSocket)
            url = req.path
            parameters = json.dumps(dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(req.path).query)))
            headers = json.dumps(dict(req.headers))
            cookies = json.dumps(dict(http.cookies.SimpleCookie(req.headers.get('Cookie'))))
            response_headers = json.dumps(dict(res.headers))
            
            ssl_info = None
            if is_https:
                ssl_info = json.dumps({
                    'version': req.connection.version(),
                    'cipher': req.connection.cipher(),
                })

            # Convert res_body to string if it's bytes
            if isinstance(res_body, bytes):
                res_body = res_body.decode('utf-8', errors='replace')

            values = (
                url, is_https, parameters, req.command, req.request_version,
                headers, cookies, res.status, response_headers, res_body, ssl_info
            )

            logger.info(f"Executing SQL query for URL: {url}")
            cursor.execute(query, values)
            conn.commit()
            logger.info(f"Data successfully stored in database for URL: {url}")

        except mysql.connector.Error as err:
            logger.error(f"Database error for URL {req.path}: {err}")
            logger.error(f"Error code: {err.errno}")
            logger.error(f"SQL State: {err.sqlstate}")
            logger.error(f"Error message: {err.msg}")
        except Exception as e:
            logger.error(f"Unexpected error for URL {req.path}: {e}")
            logger.debug(traceback.format_exc())
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'conn' in locals():
                conn.close()
        logger.info(f"Exiting store_request_data for URL: {req.path}")

    def validate_data(self, req, req_body, res, res_body):
        # URL 길이 체크
        if len(req.path) > 2083:  # 일반적인 URL 최대 길이
            logger.warning(f"URL too long: {req.path[:100]}...")
            return False
        
        # 응답 본문 크기 체크
        if len(res_body) > 10 * 1024 * 1024:  # 10MB 제한
            logger.warning(f"Response body too large for URL: {req.path}")
            return False
        
        # 기타 필요한 검증 로직 추가
        
        return True

    def send_response_body(self, body):
        try:
            if len(body) > 8192:  # 8KB 이상인 경우 청크 전송
                self.send_header('Transfer-Encoding', 'chunked')
                self.end_headers()
                for i in range(0, len(body), 8192):
                    chunk = body[i:i+8192]
                    self.wfile.write(f"{len(chunk):X}\r\n".encode())
                    self.wfile.write(chunk)
                    self.wfile.write(b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            else:
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            logger.warning("Client disconnected")
        except Exception as e:
            logger.error(f"Error sending response body: {e}")
            logger.debug(traceback.format_exc())
            
    def finish_request(self):
        try:
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            logger.warning("Client disconnected")
        except Exception as e:
            logger.error(f"Error in finish_request: {e}")
            logger.debug(traceback.format_exc())
        finally:
            try:
                self.connection.shutdown(socket.SHUT_WR)
            except:
                pass

def run_proxy(host='localhost', port=7777):
    server_address = (host, port)
    httpd = http.server.ThreadingHTTPServer(server_address, ProxyInterceptor)
    logger.info(f'Starting proxy server on {host}:{port}')
    httpd.serve_forever()

if __name__ == '__main__':
    run_proxy()