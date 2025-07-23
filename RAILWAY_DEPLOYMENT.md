# Railway Deployment Guide

## Quick Deployment Steps

1. **Login to Railway**
   ```bash
   npx @railway/cli login
   ```

2. **Initialize Railway project**
   ```bash
   railway init
   ```

3. **Set environment variables**
   ```bash
   railway variables set AES_KEY=$(openssl rand -hex 32)
   railway variables set HMAC_KEY=$(openssl rand -hex 32)
   railway variables set BASE_URL=https://your-project-name.up.railway.app
   railway variables set PORT=3000
   ```

4. **Deploy**
   ```bash
   railway up
   ```

5. **Get your Railway URL**
   ```bash
   railway domain
   ```

## Environment Variables

- `AES_KEY`: 32-byte hex key for URL encryption
- `HMAC_KEY`: 32-byte hex key for signature verification
- `BASE_URL`: Your Railway app URL (https://your-project.up.railway.app)
- `PORT`: 3000 (Railway default)
- `IPQS_API_KEY`: (Optional) IP Quality Score API key

## Testing Your Deployment

1. **Create an alias**:
   ```bash
   curl -X POST 'https://your-project.up.railway.app/alias/create' \
   --header 'Content-Type: application/json' \
   --data '{
     "url": "https://calendly.com/illuvium-alpha/early-access",
     "alias": "early-access-signup"
   }'
   ```

2. **Test redirect**:
   ```bash
   curl -I 'https://your-project.up.railway.app/r/early-access-signup'
   ```

## Update Mailer Configuration

After deployment, update your `config/mailer_config.json`:

```json
{
  "email_settings": {
    "tracking": {
      "enable_railway_tracking": true,
      "railway_base_url": "https://your-actual-railway-domain.up.railway.app",
      "enable_email_tracking": false,
      "pixel_enabled": false,
      "click_tracking_enabled": false
    }
  }
}
```

## Features

- ✅ Secure URL encryption with AES-256-CBC
- ✅ HMAC-SHA256 signatures for integrity
- ✅ Clean, memorable aliases
- ✅ Bot protection (optional)
- ✅ Click tracking and analytics
- ✅ No complex pixel tracking (clean emails)

## Security

- All URLs are encrypted before storage
- HMAC signatures prevent tampering
- Optional IP reputation checking
- Rate limiting enabled
- No personal data stored
