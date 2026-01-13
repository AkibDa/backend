
# app/webhook.py

import os
import hmac
import hashlib
from fastapi import APIRouter, Request, HTTPException
from firebase_admin import firestore
from .firebase_init import db

router = APIRouter()


@router.post("/webhook/razorpay", tags=["webhook"])
async def razorpay_webhook(request: Request):
  signature = request.headers.get('X-Razorpay-Signature')
  secret = os.environ.get("RAZORPAY_WEBHOOK_SECRET")
  body = await request.body()

  try:
    expected_signature = hmac.new(
      key=secret.encode(),
      msg=body,
      digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, signature):
      raise HTTPException(status_code=400, detail="Invalid signature")
  except Exception:
    raise HTTPException(status_code=400, detail="Signature verification failed")

  payload = await request.json()
  event_type = payload.get('event')

  if event_type in ['payment.captured', 'payment_link.paid']:
    payment = payload['payload']['payment']['entity']
    notes = payment.get('notes', {})

    internal_order_id = notes.get('internal_order_id')
    payment_id = payment.get('id')

    if internal_order_id:
      order_ref = db.collection('orders').document(internal_order_id)
      order_ref.update({
        "status": "PAID",
        "payment_id": payment_id,
        "razorpay_payment_data": payment,
        "updated_at": firestore.SERVER_TIMESTAMP
      })
      print(f"✅ Order {internal_order_id} marked as PAID")
    else:
      print(f"⚠️ Payment received without internal_order_id: {payment['id']}")

  return {"status": "ok"}
