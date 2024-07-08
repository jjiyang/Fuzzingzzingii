import os
import ssl
from subprocess import Popen
import shutil
import glob

def create_ssl_context(cert_path, key_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    return context

def generate_certificates(config):
    Popen(["openssl", "genrsa", "-out", config.ca_key, "2048"]).communicate()
    Popen([
        "openssl", "req", "-new", "-x509", "-days", "3650", "-key", config.ca_key,
        "-sha256", "-out", config.ca_cert, "-subj", "/CN=FuzzingzzingiCA"
    ]).communicate()
    Popen(["openssl", "genrsa", "-out", config.cert_key, "2048"]).communicate()
    os.makedirs(config.cert_dir, exist_ok=True)
    for old_cert in glob.glob(os.path.join(config.cert_dir, "*.pem")):
        os.remove(old_cert)
    try:
        csr_process = Popen(csr_command, stdout=PIPE, stderr=PIPE)
        csr, err = csr_process.communicate()
        if csr_process.returncode != 0:
            print(f"CSR 생성 오류: {err.decode()}")
            return False

        cert_process = Popen(cert_command, stdin=PIPE, stderr=PIPE)
        _, err = cert_process.communicate(input=csr)
        if cert_process.returncode != 0:
            print(f"인증서 서명 오류: {err.decode()}")
            return False
    except Exception as e:
        print(f"인증서 생성 중 예외 발생: {e}")
        return False

    print(f"Certificate generated successfully for {hostname}")
    return True    

def create_example_handlers():
    example_file = os.path.join(os.path.dirname(__file__), "examples/handler_example.py")
    shutil.copy(example_file, "custom_handlers_example.py")