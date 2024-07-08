from server_core import run_proxy_server
from settings import parse_config
from cert_manager import generate_certificates, create_example_handlers

def main():
    config = parse_config()
    
    if config.generate_certs:
        generate_certificates(config)
        return
    
    if config.create_example:
        create_example_handlers()
        return
    
    run_proxy_server(config)

if __name__ == "__main__":
    main()