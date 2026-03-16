import ssl
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print

# Configuration matches your Docker setup
HOST = '127.0.0.1'
PORT = 9390
USER = 'admin'
PASS = '1234'

def verify():
    print(f"[*] Attempting to connect to {HOST}:{PORT}...")
    
    # Configure SSL to trust the self-signed certs of the container
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        # 1. Establish TLS Connection
        connection = TLSConnection(hostname=HOST, port=PORT, ssl_context=context)
        
        # 2. Initialize GMP Protocol
        transform = EtreeTransform()
        with Gmp(connection=connection, transform=transform) as gmp:
            # 3. Authenticate
            print("[*] Connection established. Authenticating...")
            gmp.authenticate(USER, PASS)
            
            # 4. Get Version (Proof of life)
            version = gmp.get_version()
            print("[+] SUCCESS! Connected to Greenbone Management Protocol.")
            print("[*] GMP Version Details:")
            pretty_print(version)

    except Exception as e:
        print(f"[-] CONNECTION FAILED: {e}")
        print("\nPossible fixes:")
        print("1. Ensure your docker containers are running: 'docker ps'")
        print("2. Check if gvmd is listening on 9390 in your docker-compose.yml")
        print("3. Verify the 'admin' password is correct.")

if __name__ == "__main__":
    verify()