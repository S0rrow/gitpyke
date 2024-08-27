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
            return secrets["smtp"], secrets["emails"], secrets["branches"]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading secrets: {e}")

class WebhookPayload(BaseModel):
    ref: str
    repository: dict
    pusher: dict
    
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")

def verify_signature(signature: str, payload: str) -> bool:
    # check if signature is valid
    if signature is None or signature == "":
        raise HTTPException(status_code=400, detail="Missing signature")
    # check if payload is valid json
    payload_str = payload.decode("utf-8")
    try:
        json.loads(payload_str)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid payload")
    # check if signature is valid with github webhook secret
    # but if WEBHOOK_SECRET is not set, return True
    if WEBHOOK_SECRET is None or WEBHOOK_SECRET == "":
        return True
    expected_signature = hmac.new(
        key=WEBHOOK_SECRET.encode(),
        msg=payload.encode(),
        digestmod=hashlib.sha1
    ).hexdigest()
    return hmac.compare_digest(f"sha1={expected_signature}", signature)

async def validate_webhook(request: Request):
    signature = request.headers.get("X-Hub-Signature")
    payload_data = await request.body()
    payload_str = payload_data.decode("utf-8")

    if signature and not verify_signature(signature, payload_str):
        raise HTTPException(status_code=401, detail="Invalid signature")
    # check if payload is valid json
    try:
        json.loads(payload_str)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid payload")
    return json.loads(payload_str)

def send_email_and_respond(smtp_config, email_config, subject, body, recipients=None):
    try:
        if send_email(smtp_config, email_config, subject, body, recipients):
            return {"message": "Email sent successfully"}
        else:
            return {"message": "Email not sent"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.debug(f"Received request: {request.method} {request.url}")
    logger.debug(f"Headers: {request.headers}")
    body = await request.body()
    logger.debug(f"Body: {body.decode()}")
    response = await call_next(request)
    return response

def send_email(smtp_config, email_config, subject, body, recipients=None)->bool:
    msg = MIMEMultipart()
    msg['From'] = smtp_config['username']
    if recipients is None:
        msg['To'] = ", ".join(email_config['recipients'])
    else:
        # recipients is list of nicknames, where email_config['nicknames'] is dict of {nickname: email}
        msg['To'] = ", ".join([email_config['nicknames'][nickname] for nickname in recipients])
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
        return True
    except Exception as e:
        raise e
    
@app.post("/push/")
async def github_push_webhook(request: Request):
    payload = await validate_webhook(request)
    smtp_config, email_config, branch_config = load_smtp_config()
    recipients = None

    # Check if the event is a push event
    if "pusher" not in payload:
        return {"message": "Not a push event, no action taken"}
    
    ref = payload.get("ref", "")
    branches_to_watch = ", ".join(branch_config['overwatch'])
    branch_name = ref.replace('refs/heads/', '', 1)
    
    if branch_name not in branches_to_watch.split(", "):
        return {"message": "Branch not monitored, no action taken"}
    
    subject = f"GitHub Push Event occurred in '{branch_name}'"
    body = (f"Repository: {payload.get('repository', {}).get('full_name', 'Unknown')}\n"
            f"Pushed By: {payload.get('pusher', {}).get('name', 'Unknown')}\n"
            f"Branch: {branch_name}\n"
            f"Details: {payload.get('head_commit', {}).get('message', 'No commit message')}\n")
    
    return send_email_and_respond(smtp_config, email_config, subject, body, recipients)

# from payload, get the assignee's nickname and send email only to the assignee
@app.post("/issue/")
async def github_issue_webhook(request: Request):
    payload = await validate_webhook(request)
    smtp_config, email_config, _ = load_smtp_config()
    recipients = None
    # if event is not issue, return
    if payload.get("action") is None or "issue" not in payload:
        return {"message": "Invalid issue event payload"}
    
    action = payload.get("action", "")
    if action not in ["opened", "closed", "assigned", "reopened"]:
        return {"message": "Issue event ignored"}
    # assignees is inside issue
    assignees = payload.get("issue", {}).get("assignees", [])
    if len(assignees) == 0:
        return {"message": "Issue not assigned to anyone, no action taken"}
    # email_config['nicknames'] is dict of {nickname: email} where each nickname and email is string
    assignee_nicknames = [email_config['nicknames'].get(assignee, None) for assignee in assignees]
    # remove None from assignee_nicknames
    assignee_nicknames = [nickname for nickname in assignee_nicknames if nickname is not None]
    recipients = assignee_nicknames
    # apply action to subject with only first letter capitalized
    action = action.capitalize()
    done_by = payload.get("sender", {}).get("login", "Unknown")
    subject = f"GitHub Issue Event {action} by {done_by}"
    body = (f"Repository: {payload.get('repository', {}).get('full_name', 'Unknown')}\n"
            f"Issue: {payload.get('issue', {}).get('title', 'Unknown')}\n"
            f"Details: {payload.get('issue', {}).get('body', 'No body')}\n"
            f"Link: {payload.get('issue', {}).get('url', 'No link')}\n")
    
    return send_email_and_respond(smtp_config, email_config, subject, body, recipients)

@app.post("/repository_vulnerability/")
async def github_vulnerability_webhook(request: Request):
    payload = await validate_webhook(request)
    smtp_config, email_config, _ = load_smtp_config()
    recipients = None
    # Check if the event is a repository vulnerability alert
    if payload.get("alert", {}).get("external_identifier") is None:
        return {"message": "Not a repository vulnerability alert event, no action taken"}
    branch_name = payload.get("repository", {}).get("default_branch", "Unknown")
    
    subject = f"GitHub Repository Vulnerability Alert occurred in '{branch_name}'"
    body = (f"Repository: {payload.get('repository', {}).get('full_name', 'Unknown')}\n"
            f"Vulnerability: {payload.get('vulnerability', {}).get('package', {}).get('name', 'Unknown')}\n"
            f"Details: {payload.get('vulnerability', {}).get('advisory', {}).get('summary', 'No summary')}\n"
            f"Link: {payload.get('vulnerability', {}).get('advisory', {}).get('url', 'No link')}\n")
    
    return send_email_and_respond(smtp_config, email_config, subject, body, recipients)

@app.post("/pull_request/")
async def github_pull_request_webhook(request: Request):
    payload = await validate_webhook(request)
    smtp_config, email_config, branch_config = load_smtp_config()
    recipients = None
    branches_to_watch = ", ".join(branch_config['overwatch'])
    # Check if the event is a pull request
    if "pull_request" not in payload:
        return {"message": "Not a pull request event, no action taken"}
    
    # check the branch name where pull request is created
    branch_name = payload.get("pull_request", {}).get("base", {}).get("ref", "Unknown")
    # if branch name is not in the list of branches to watch, return
    if branch_name not in branches_to_watch.split(", "):
        return {"message": "Branch not monitored, no action taken"}
    
    action = payload.get("action", "")
    if action not in ["opened", "closed", "commented", "reopened"]:
        return {"message": "Pull request event ignored"}
    done_by = payload.get("sender", {}).get("login", "Unknown")
    action = action.capitalize()
    subject = f"GitHub Pull Request {action} by {done_by}"
    body = (f"Repository: {payload.get('repository', {}).get('full_name', 'Unknown')}\n"
            f"Pull Request: {payload.get('pull_request', {}).get('title', 'Unknown')}\n"
            f"Details: {payload.get('pull_request', {}).get('body', 'No body')}\n"
            f"Link: {payload.get('pull_request', {}).get('url', 'No link')}\n")
    
    return send_email_and_respond(smtp_config, email_config, subject, body, recipients)

