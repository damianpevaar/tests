import ssl
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from pyngrok import ngrok

app = FastAPI(title="OpenVAS REST Middleware")

# --- CONFIGURATION ---
OPENVAS_HOST = '127.0.0.1'
OPENVAS_PORT = 9390
OPENVAS_USER = 'admin'
OPENVAS_PASS = '1234' # Change this to your actual password!

# Standard IDs for Greenbone 24.10
SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"
CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
PORT_LIST_ID = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"

class ScanRequest(BaseModel):
    target_ip: str
    target_name: str = "Scan from Linux Terminal"

def get_gmp_connection():
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        connection = TLSConnection(
            hostname=OPENVAS_HOST,
            port=OPENVAS_PORT,
            ssl_context=context
        )
        
        gmp = Gmp(connection=connection, transform=EtreeTransform())
        gmp.authenticate(OPENVAS_USER, OPENVAS_PASS)
        return gmp
    except Exception as e:
        print(f"[-] Connection Error: {str(e)}")
        raise

@app.post("/api/scan")
def start_scan(request: ScanRequest):
    try:
        with get_gmp_connection() as gmp:
            # 1. Create Target
            target_res = gmp.create_target(
                name=f"TGT-{request.target_ip}",
                hosts=[request.target_ip],
                port_list_id=PORT_LIST_ID
            )
            target_id = target_res.xpath('@id')

            # 2. Create Task
            task_res = gmp.create_task(
                name=f"Task-{request.target_ip}",
                config_id=CONFIG_ID,
                target_id=target_id,
                scanner_id=SCANNER_ID
            )
            task_id = task_res.xpath('@id')

            # 3. Start Task
            gmp.start_task(task_id)

            return {"status": "success", "task_id": task_id, "target": request.target_ip}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    # Optional: ngrok logic can be handled via CLI, but kept here for compatibility
    try:
        public_url = ngrok.connect(8000).public_url
        print(f"\n[+] API TUNNEL: {public_url}/api/scan\n")
    except:
        print("\n[!] Ngrok not configured or failed. Access locally at http://127.0.0.1:8000\n")
        
    uvicorn.run(app, host="0.0.0.0", port=8000)