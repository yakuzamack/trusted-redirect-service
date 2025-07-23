# Trusted Redirect Service

A secure URL tracking and redirect service for email campaigns.

## Features

- **Secure URL Encryption**: All URLs are encrypted with AES-256-CBC and signed with HMAC-SHA256
- **Alias Support**: Create memorable aliases for long URLs
- **Bot Protection**: IP reputation checking with IPQualityScore (optional)
- **Railway Ready**: Configured for Railway deployment

## Local Testing

1. Install dependencies:
```bash
npm install
```

2. Set environment variables:
```bash
export AES_KEY=$(openssl rand -hex 32)
export HMAC_KEY=$(openssl rand -hex 32)
export BASE_URL=http://localhost:3002
export PORT=3002
```

3. Start the service:
```bash
npm start
```

4. Test alias creation:
```bash
curl -X POST 'http://localhost:3002/alias/create' \
--header 'Content-Type: application/json' \
--data '{
  "url": "https://google.com",
  "alias": "myalias123"
}'
```

5. Test redirect:
```bash
curl -I 'http://localhost:3002/r/myalias123'
```

## Railway Deployment

1. Login to Railway:
```bash
railway login
```

2. Create a new project:
```bash
railway new
```

3. Set environment variables:
```bash
railway variables set AES_KEY=$(openssl rand -hex 32)
railway variables set HMAC_KEY=$(openssl rand -hex 32)
railway variables set BASE_URL=https://your-domain.up.railway.app
```

4. Deploy:
```bash
railway up
```

## API Endpoints

### Create Alias
- **POST** `/alias/create`
- **Body**: `{"url": "https://example.com", "alias": "myalias"}`
- **Response**: `{"alias": "myalias", "redirectUrl": "https://domain.com/r/myalias"}`

### Redirect
- **GET** `/r/{alias}`
- Redirects to the original URL

### Create Encrypted URL
- **GET** `/create?url=https://example.com`
- Returns encrypted redirect URL

## Integration with Mailer

The mailer will create aliases for tracking URLs and use the Railway service for redirects only. No email-level tracking pixels are used.
