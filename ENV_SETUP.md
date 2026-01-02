# Environment Variables Setup

## Required Environment Variables

Create a `.env` file in the `Backend` directory with the following variables:

```env
# Flask Configuration
ENV=production
SECRET_KEY=your-secret-key-here

# Database Configuration
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=localhost
DB_PORT=3306
DB_NAME_ADMIN=impromptuindian_admin
DB_NAME_CUSTOMER=impromptuindian_customer
DB_NAME_VENDOR=impromptuindian_vendor
DB_NAME_RIDER=impromptuindian_rider
DB_NAME_SUPPORT=impromptuindian_support

# Email Configuration (SMTP)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com

# MSG91 Configuration
# Get Authkey from: Dashboard -> API -> Authkey
MSG91_AUTHKEY=your_msg91_authkey_here

# MSG91 OTP Widget Configuration (REQUIRED)
# Get from: OTP -> Widgets -> Create Widget
MSG91_WIDGET_ID=356c456c7171393439393539
MSG91_TOKEN_AUTH=485626TyjvgxxvJp6955161dP1

# MSG91 Sender ID (6 characters, alphanumeric)
# Create at: SMS -> Sender ID
MSG91_SENDER_ID=IMPRTU

# MSG91 Route (1=Promotional, 4=Transactional)
# Default: 4 (Transactional) - recommended for OTP
MSG91_ROUTE=4

# Optional: DLT Template ID (if you have registered template)
MSG91_DLT_TE_ID=

# API Keys
MAPPLS_API_KEY=your_mappls_api_key_here

# Domain Configuration
BASE_DOMAIN=impromptuindian.com
APP_SUBDOMAIN=apparels
VENDOR_SUBDOMAIN=vendor
RIDER_SUBDOMAIN=rider

# CORS Configuration
ALLOWED_ORIGINS=https://apparels.impromptuindian.com,https://vendor.impromptuindian.com,https://rider.impromptuindian.com

# Session Configuration
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
```

## For cPanel Deployment

Add these environment variables in cPanel:
1. Go to **Environment Variables** in cPanel
2. Add each variable with its value
3. Restart your Passenger application

## Important Notes

- **Never commit `.env` file to version control**
- MSG91 credentials are now **required** (no hardcoded defaults)
- If `MSG91_WIDGET_ID` or `MSG91_TOKEN_AUTH` are missing, the OTP widget will not work
- The backend will return an error if widget credentials are not configured

