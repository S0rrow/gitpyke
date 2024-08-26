import hmac
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import hashlib

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

WEBHOOK_SECRET = "webhook_secret"

def verify_signature(signature: str, payload: str) -> bool:
    # 비밀 키를 사용하여 HMAC-SHA1 해시를 생성하고 서명을 검증
    expected_signature = hmac.new(
        key=WEBHOOK_SECRET.encode(),
        msg=payload.encode(),
        digestmod=hashlib.sha1
    ).hexdigest()
    return hmac.compare_digest(f"sha1={expected_signature}", signature)

@app.post("/webhook/")
async def github_webhook(request: Request):
    signature = request.headers.get("X-Hub-Signature")
    if signature is None:
        raise HTTPException(status_code=400, detail="Missing X-Hub-Signature header")
    
    payload_data = await request.body()
    payload_str = payload_data.decode("utf-8")
    
    if not verify_signature(signature, payload_str):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # 여기서부터는 유효한 요청만 처리함
    payload = json.loads(payload_str)
    ref = payload.get("ref", "")
    branch_name = ref.replace('refs/heads/', '', 1)
    
    smtp_config, email_config = load_smtp_config()
    
    # Check if the branch is one of the specified branches
    if branch_name in ["dev", "feature/frontend"]:
        subject = f"GitHub Push Event for Branch '{branch_name}'"
        body = (f"Repository: {payload.get('repository', {}).get('full_name', 'Unknown')}\n"
                f"Pusher: {payload.get('pusher', {}).get('name', 'Unknown')}\n"
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