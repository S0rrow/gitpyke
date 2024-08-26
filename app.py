import hmac
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import hashlib
import os
import logging

app = FastAPI()

# Load email configuration from secrets.json
def load_smtp_config():
    try:
        with open("secrets.json") as f:
            secrets = json.load(f)
            return secrets["smtp"], secrets["emails"]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading secrets: {e}")

class WebhookPayload(BaseModel):
    ref: str
    repository: dict
    pusher: dict

# Fetch webhook secret from environment variable or default to an empty string
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")

def verify_signature(signature: str, payload: str) -> bool:
    if not WEBHOOK_SECRET:
        # No secret set, skip signature verification
        return True
    
    expected_signature = hmac.new(
        key=WEBHOOK_SECRET.encode(),
        msg=payload.encode(),
        digestmod=hashlib.sha1
    ).hexdigest()
    return hmac.compare_digest(f"sha1={expected_signature}", signature)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info(f"Received request: {request.method} {request.url}")
    logger.info(f"Headers: {request.headers}")
    body = await request.body()
    logger.info(f"Body: {body.decode()}")
    response = await call_next(request)
    return response

@app.post("/webhook/")
async def github_webhook(request: Request):
    signature = request.headers.get("X-Hub-Signature")
    
    # Read and decode the payload
    payload_data = await request.body()
    payload_str = payload_data.decode("utf-8")

    # Verify signature if secret is set
    if signature and not verify_signature(signature, payload_str):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Here, we process the payload if the signature is valid or no secret is set
    payload = json.loads(payload_str)
    ref = payload.get("ref", "")
    branch_name = ref.replace('refs/heads/', '', 1)
    
    smtp_config, email_config = load_smtp_config()
    
    # Check if the branch is one of the specified branches
    if branch_name in ["dev", "feature/frontend"]:
        subject = f"GitHub Push Event for Branch '{branch_name}'"
        body = (f"Repository: {payload.get('repository', {}).get('full_name', 'Unknown')}\n"
                f"Pushed By: {payload.get('pusher', {}).get('name', 'Unknown')}\n"
                f"Branch: {branch_name}\n"
                f"Details: {payload.get('head_commit', {}).get('message', 'No commit message')}\n")

        # Prepare email
        msg = MIMEMultipart()
        msg['From'] = smtp_config['username']
        msg['To'] = ", ".join(email_config['recipients'])
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        try:
            # Send email
            server = smtplib.SMTP(smtp_config['smtp_server'], smtp_config['smtp_port'])
            server.starttls()  # Secure the connection
            server.login(smtp_config['username'], smtp_config['password'])
            text = msg.as_string()
            server.sendmail(smtp_config['username'], email_config['recipients'], text)
            server.quit()
            return {"message": "Email sent successfully"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    return {"message": "Branch not monitored, no action taken"}