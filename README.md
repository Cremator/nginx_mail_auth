# Mail Auth Proxy for Nginx (IMAP/SMTP)

A lightweight Go authentication backend designed specifically for the **Nginx mail proxy module**.

It validates user credentials against IMAP and/or SMTP servers and enforces rate limiting and temporary blocking to protect against brute-force attacks.

---

## 🎯 Purpose

This service is built to act as an **`auth_http` backend** for Nginx mail proxy:

- Nginx handles client connections (IMAP/SMTP)
- This service validates credentials
- Returns upstream mail server to Nginx

---

## ✨ Features

- 🔐 IMAP & SMTP authentication backend
- 🔁 Optional IMAP-only mode (use IMAP for SMTP auth)
- 🚫 Brute-force protection (per IP + per user)
- ⏱️ Expiring blocks with configurable TTL
- ⚡ Fast in-memory HTTP auth service
- 🧩 Drop-in replacement for Nginx `auth_http`

---

## 🏗️ Architecture

```
Mail Client
    ↓
IMAP / SMTP
    ↓
Nginx mail proxy
    ↓
auth_http request
    ↓
Mail Auth Proxy (this service)
    ↓
IMAP / SMTP servers
```

---

## 🚀 Build & Run

```bash
git clone <repo>
cd <repo>
go build -o nginx_mail_auth

./nginx_mail_auth   --imap 127.0.0.1:143,127.0.0.2:143   --smtp 127.0.0.1:25   --port 9143
```

---

## ⚙️ Nginx Configuration

### IMAP example

```nginx
mail {
    server_name mail.example.com;

    auth_http 127.0.0.1:9143;

    imap {
        listen 143;
        protocol imap;
    }
}
```

---

### SMTP example

```nginx
mail {
    server_name mail.example.com;

    auth_http 127.0.0.1:9143;

    smtp {
        listen 25;
        protocol smtp;
    }
}
```

---

### Full setup (IMAP + SMTP)

```nginx
mail {
    server_name mail.example.com;
    auth_http   nginx_mail_auth:9143/auth;

    proxy_pass_error_message on;

    ssl                 on;
    ssl_certificate     /certificates/example.com.crt;
    ssl_certificate_key /certificates/example.com.key;
    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    server {
        listen          587;
        protocol        smtp;
        proxy_smtp_auth on;
        smtp_auth       login plain cram-md5;
    }

     server {
        listen   993;
        protocol imap;
    }
}
```

---

## 📡 Nginx → Auth Backend Headers

| Header | Description |
|--------|------------|
| Auth-Method | Authentication method (must be `plain`) |
| Auth-User | Username |
| Auth-Pass | Password |
| Auth-Protocol | `imap` or `smtp` |
| Auth-Login-Attempt | Login attempt counter |
| Client-IP | Client IP address |

---

## ✅ Responses

### Success

```
Auth-Status: OK
Auth-Server: <backend server>
Auth-Port: <port>
```

---

### Failure

```
Auth-Status: Invalid credentials
Auth-Wait: <seconds>
```

---

### SMTP temporary error

```
Auth-Status: Temporary server problem, try again later
Auth-Error-Code: <smtp error>
```

---

## 🛡️ Rate Limiting

- Per-IP tracking
- Per-user tracking
- Automatic expiration

Behavior:
- Exceed max attempts → temporary block
- Each failure increases penalty
- TTL-based cleanup

---

## ⚙️ CLI Flags

```bash
--imap host:port
--smtp host:port
--port 9143
--maxinvalidattempts 5
--invalidduration 5m
--useimaponly
```

---

## 💡 Recommended Nginx Settings

```nginx
mail {
    auth_http_timeout 10s;
    proxy_pass_error_message on;
    max_errors 3;
}
```

---

## 🔒 TLS Notes

This service does NOT handle TLS.

Use Nginx for:
- IMAPS (993)
- SMTPS (465)

Keep service internal only.

---

## ⚠️ Limitations

- SMTP only AUTH LOGIN
- No TLS backend support
- No persistent storage
- No clustering

---

## 🧪 Test Request

```bash
curl -i http://127.0.0.1:9143 \
  -H "Auth-Method: plain" \
  -H "Auth-User: user@example.com" \
  -H "Auth-Pass: password" \
  -H "Auth-Protocol: imap" \
  -H "Auth-Login-Attempt: 1" \
  -H "Client-IP: 127.0.0.1"
```

---

## 📌 Production Tips

- Bind to localhost/private interface
- Firewall restrict access
- Monitor logs for brute force
- Use Redis if scaling

---

## 📄 License

MIT
