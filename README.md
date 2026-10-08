# AARPI Print Portal — Auth + Admin Panel

## Admin features
- Admin-only login at `/admin/login`
- Dashboard overview/statistics
- Member management: view members and delete member accounts
- Password-reset request management: view active reset requests and invalidate them
- Service-card management: add, hide/activate, and delete service cards
- Wallet management: credit/debit member balances with validation and transaction logging
- Account activity: view wallet/account activity across members
- Role-based access control: only users with `role=admin` can access `/admin/*`

## Member features
- Registration
- Login/logout
- Forgot-password and single-use 30-minute reset tokens
- Protected member dashboard
- Service cards and wallet/activity display

## Setup

1. Install Node.js 20+.
2. Extract the project.
3. Run:
   ```bash
   npm install
   ```
4. Copy `.env.example` to `.env`.
5. Set a strong `SESSION_SECRET`.
6. Set `ADMIN_EMAIL` and a strong `ADMIN_PASSWORD` (12+ characters) for the first admin.
7. Start:
   ```bash
   npm start
   ```
8. Open:
   - Member login: `http://localhost:3000/login`
   - Admin login: `http://localhost:3000/admin/login`

The first server start creates the admin account if it does not already exist. Do not leave the example admin password in production.

## Production security
- Use HTTPS and secure cookies.
- Use a long random `SESSION_SECRET`.
- Use a managed database/backups for production.
- Configure SMTP with a verified sending domain.
- Restrict admin access with additional controls such as 2FA, IP/network restrictions, or an identity provider if the portal handles sensitive data.
- Do not store government-service passwords, OTPs, banking credentials, or other secrets.
- Keep all government/third-party service integrations limited to APIs and workflows you are authorized to use.
- Wallet adjustments are administrative accounting actions; add an approval/audit workflow before using real money.
