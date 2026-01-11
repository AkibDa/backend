# GreenPlate — Backend (FastAPI)

A compact FastAPI backend for managing college food stalls, staff, menus and orders.

Quick summary
- Auth: Firebase ID tokens (verify with firebase_admin).
- Data: Firestore collections (colleges, stalls, staffs, users, menu_items).
- AI menu extraction: optional (Google Gemini) — returns JSON list of {name, price, description}.
- Payments: Razorpay integration for creating orders and a webhook to record payments.
- Docker ready (Dockerfile + compose.yaml).

Quick start (local)
1. Create & activate a virtualenv:

```bash
python -m venv .venv && source .venv/bin/activate
```

2. Install deps:

```bash
pip install -r requirements.txt
```

3. Provide Firebase & other secrets (recommended via `.env` or env vars). Important vars listed below.

4. Run the app:

```bash
python main.py
# or
uvicorn app.app:app --reload --host 0.0.0.0 --port 8000
```

Docker
- Build and run container:

```bash
docker build -t greenplate-backend .
docker run --rm -p 8000:8000 --env-file .env -v $(pwd)/secrets:/app/secrets:ro greenplate-backend
```

- With Compose (repo root):

```bash
docker compose up --build
docker compose down
```

Authentication
- Use Firebase ID token (NOT the UID). Send in Authorization header as a Bearer token:

```
Authorization: Bearer <idToken>
```

- Obtain a test idToken via `/login/users` or the helper `get_token.py` (dev-only).

Key environment variables
- FIREBASE_SERVICE_ACCOUNT: JSON content or path for firebase_admin credentials (required).
- FIREBASE_API_KEY, FIREBASE_AUTH_DOMAIN, FIREBASE_DATABASE_URL, FIREBASE_PROJECT_ID, FIREBASE_STORAGE_BUCKET, FIREBASE_MESSAGING_SENDER_ID, FIREBASE_APP_ID, FIREBASE_MEASUREMENT_ID — used by the auth client and helper scripts.
- GEMINI_API_KEY — optional, required for image-based menu scanning.
- RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET — required for payment order creation.
- RAZORPAY_WEBHOOK_SECRET — secret used to validate incoming Razorpay webhook signatures (used by `/webhook/razorpay`).

Important files
- `app/firebase_init.py` — initializes firebase_admin and exposes `db` (Firestore client).
- `app/auth.py` — verifies tokens and initializes manager records when a manager signs in using the stall email.
- `app/schema.py` — Pydantic models (MenuSchema, MenuItemSchema, MenuScanResponse, CreateOrderSchema, etc.).
- `app/staff.py` — staff routes logic: upload/get/update/delete menus, add staff, image scan.
- `app/manager.py` — manager-only helpers: list staff, remove staff, update staff email.
- `app/user.py` — student-facing: list menus and create payment orders.
- `app/webhook.py` — Razorpay webhook: validates HMAC signature (X-Razorpay-Signature) and saves successful payments to Firestore `orders` collection.
- `get_token.py` — helper to exchange email/password for idToken (dev/test only).

Core rules / behavior (short)
- Staff authorization is enforced by token -> `staffs` lookup. A staff can only manage the stall they belong to (stall_id check).
- Manager init: when a user signs in and their email matches a stall's email (in that college), a manager `staffs` document is created automatically.
- Menu upload expects JSON matching `MenuSchema` (see `app/schema.py`):
  - stall_id: string (must equal authenticated staff's stall)
  - items: list of {name: str, price: float (>0), description?: str, is_available?: bool}
- Image scan returns a JSON array of extracted items. Results must be reviewed before saving.

API (selected endpoints)
- GET /health — health check

Auth
- POST /auth/verify-staff — Verify staff token; initializes manager if needed.
- POST /auth/verify-student — Verify student token and auto-register student (by college domain).

User (student)
- GET /user/menu — List menus for the student's college (only active & verified stalls returned).
- POST /user/order/create — Create a Razorpay order (payload: CreateOrderSchema)

Staff / Manager
- POST /staff/add-member — Manager adds a staff (payload: {email})
- GET /staff/list — Manager: list staff for manager's stall
- DELETE /staff/{staff_uid} — Manager: remove a staff member (must be same stall)
- PUT /staff/{staff_uid}/email — Manager: change a staff's email (creates user if needed)

Menu management (staff/manager)
- POST /staff/menu — Upload menu JSON for the authenticated staff's stall (MenuSchema)
- GET /staff/menu — Get menu for authenticated staff's stall
- POST /staff/menu/scan-image — Upload image (JPEG/PNG, <5MB) → returns MenuScanResponse (requires GEMINI_API_KEY)
- PATCH /staff/menu/{item_id} — Update a menu item
- DELETE /staff/menu/{item_id} — Delete a menu item

Webhook
- POST /webhook/razorpay — Receives Razorpay events, validates `X-Razorpay-Signature` using `RAZORPAY_WEBHOOK_SECRET`, and stores successful payments in Firestore `orders` collection. Configure your Razorpay webhook to point to this endpoint.

Testing & troubleshooting
- Swagger UI: http://localhost:8000/docs — use the Authorize button and paste the idToken (Bearer token).
- If you see {"message":"Authorization header required"} or 401: ensure header name is exactly `Authorization` and value starts with `Bearer ` followed by the idToken.
- If token expired or invalid: re-login to get a fresh idToken.

Security notes
- Do NOT commit secrets. The repo includes a `secrets/` folder in .gitignore — keep service account JSON and .env out of VCS.
- The server uses Firestore security via server-side checks: stall_id and college_id are validated in code before writes.

Where to look next (dev pointers)
- To change menu schema, edit `app/schema.py` (Pydantic models used for validation).
- To modify staff authorization behavior, check `app/auth.py` and `app/staff.py:get_staff_details`.
- GEMINI integration is in `app/staff.py` (_extract_menu_from_image) and requires `GEMINI_API_KEY`.

Short checklist for running locally
1. Populate `.env` (or export env vars). Ensure FIREBASE_SERVICE_ACCOUNT is set.
2. pip install -r requirements.txt
3. uvicorn app.app:app --reload --host 0.0.0.0 --port 8000
4. Use Swagger or a REST client. Authorize with `Authorization: Bearer <idToken>`.

License
- See LICENSE in repo root.

Last updated: 2026-01-11
