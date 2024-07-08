import argparse
import importlib
from utils import log_request_info

def parse_config():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-b", "--bind-address", default="localhost", help="Host to bind")
    parser.add_argument("-p", "--port", type=int, default=7777, help="Port to bind")
    parser.add_argument(
        "-d",
        "--intercept-domain",
        default="*",
        help="Domain to intercept, if not set, intercept all.",
    )
    parser.add_argument(
        "-u",
        "--userpass",
        help="Username and password for proxy authentication, format: 'user:pass'",
    )
    parser.add_argument("--timeout", type=int, default=5, help="Timeout")
    parser.add_argument("--ca-key", default="./ca-key.pem", help="CA key file")
    parser.add_argument("--ca-cert", default="./ca-cert.pem", help="CA cert file")
    parser.add_argument("--cert-key", default="./cert-key.pem", help="site cert key file")
    parser.add_argument("--cert-dir", default="./certs", help="Site certs files")
    parser.add_argument(
        "--pre-request-handler",
        help="Pre-request handler function, example: module.submodule:handle_request",
    )
    parser.add_argument(
        "--post-response-handler",
        help="Post-response handler function, example: module.submodule:handle_response",
    )
    parser.add_argument(
        "--logging-handler",
        help="Logging handler function, use 'off' to turn off, example: module.submodule:handle_logging",
    )
    parser.add_argument(
        "--generate-certs", action="store_true", help="Create https intercept certs"
    )
    parser.add_argument(
        "--create-example",
        action="store_true",
        help="Create an intercept handlers example python file",
    )
    config = parser.parse_args()

    global pre_request_hook, post_response_hook, logging_hook

    if config.pre_request_handler:
        module, func = config.pre_request_handler.split(":")
        m = importlib.import_module(module)
        pre_request_hook = getattr(m, func)
    else:
        pre_request_hook = None

    if config.post_response_handler:
        module, func = config.post_response_handler.split(":")
        m = importlib.import_module(module)
        post_response_hook = getattr(m, func)
    else:
        post_response_hook = None

    if config.logging_handler:
        if config.logging_handler == "off":
            logging_hook = None
        else:
            module, func = config.logging_handler.split(":")
            m = importlib.import_module(module)
            logging_hook = getattr(m, func)
    else:
        logging_hook = log_request_info

    return config

config = parse_config()

# Database configuration
db_settings = {
    'host': 'localhost',
    'user': 'root',
    'password': '!Ru7eP@ssw0rD!12',
    'database': 'requests'
}