import streamlit as st
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Streamlit Secrets에서 SMTP 설정 불러오기
def load_smtp_config():
    config = {
        "imap_server": st.secrets["smtp"]["imap_server"],
        "imap_port": st.secrets["smtp"]["imap_port"],
        "smtp_server": st.secrets["smtp"]["smtp_server"],
        "smtp_port": st.secrets["smtp"]["smtp_port"],
        "display_name": st.secrets["smtp"]["display_name"],
        "username": st.secrets["smtp"]["username"],
        "password": st.secrets["smtp"]["password"],
    }
    return config

# 이메일 전송 함수
def send_email(to_emails, subject, body):
    config = load_smtp_config()

    # 이메일 헤더 및 본문 설정
    msg = MIMEMultipart()
    msg['From'] = config['username']
    msg['To'] = ", ".join(to_emails)
    msg['Subject'] = subject

    # 이메일 본문
    msg.attach(MIMEText(body, 'plain'))

    try:
        # SMTP 서버에 연결
        server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
        server.starttls()  # TLS 보안 연결
        server.login(config['username'], config['password'])  # 로그인
        text = msg.as_string()

        # 이메일 전송
        server.sendmail(config['username'], to_emails, text)
        server.quit()
        st.success(f"Email sent successfully to {', '.join(to_emails)}!")
    except Exception as e:
        st.error(f"Error sending email: {e}")

# Streamlit 웹 애플리케이션
st.title("GitHub Webhook Email Forwarder")

# 웹 인터페이스로 JSON 데이터 입력 받기 (Webhook payload)
st.write("Paste GitHub Webhook payload here:")
payload = st.text_area("Webhook Payload", height=300)

# Streamlit Secrets에서 recipients 리스트 불러오기
recipients = st.secrets["emails"]["recipients"]

if st.button("Process Webhook"):
    try:
        # GitHub Webhook 데이터를 파싱
        data = json.loads(payload)
        branch_name = data['ref'].split('/')[-1]  # 'refs/heads/dev'에서 'dev' 추출
        commit_message = data['head_commit']['message']
        pusher = data['pusher']['name']

        # 특정 브랜치 (예: dev)에서만 동작
        if branch_name == 'dev':
            # 이메일 내용 설정
            subject = f"Push to {branch_name} branch"
            body = f"Branch: {branch_name}\nCommit Message: {commit_message}\nPushed by: {pusher}"

            # 이메일 전송
            send_email(recipients, subject, body)
        else:
            st.warning(f"Push occurred on branch {branch_name}, not 'dev'. No email sent.")
    except Exception as e:
        st.error(f"Error processing webhook: {e}")
