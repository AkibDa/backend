#app/firebase_init.py

import os
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, firestore
import pyrebase
from .config import firebaseConfig

load_dotenv()

firebase = pyrebase.initialize_app(firebaseConfig)

firebase_credentials = os.environ.get("FIREBASE_SERVICE_ACCOUNT")

if not firebase_credentials:
    raise RuntimeError("FIREBASE_SERVICE_ACCOUNT env variable not set")

if not firebase_admin._apps:
    cred = credentials.Certificate(firebase_credentials)
    firebase_admin.initialize_app(cred)

db = firestore.client()
