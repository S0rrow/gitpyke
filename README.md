# RESTful API application for Github Webhook

## SMTP Credentials

Informations for smtp will be saved in `secrets.json`, which is ignored by gitignore.

Currently only supports Gmail smtp with IMAP.

It's internal format should look like this.

```json
{
    "smtp": {
        "imap_server": "imap.gmail.com",
        "imap_port": 993,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "your_email@gmail.com",
        "password": "your_app_password",
        "display_name": "your_display_name"
    },
    "emails":{
        "recipients":[
            "your_recipient@gmail.com"
        ]
    },
    "branches":{
        "overwatch":[
            "main"
        ]
    }
}
```

