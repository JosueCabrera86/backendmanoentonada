import os
import requests
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")


print("URL:", SUPABASE_URL)
print("KEY:", SUPABASE_SERVICE_ROLE_KEY)

email = "decombi@gmail.com"
password = "manoentonada0501"
name = "Admin Mano Entonada"

# 1️⃣ Crear usuario en Auth
auth_resp = requests.post(
    f"{SUPABASE_URL}/auth/v1/admin/users",
    headers={
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    },
    json={
        "email": email,
        "password": password,
        "email_confirm": True,
    },
)

if auth_resp.status_code not in (200, 201):
    print("Error creando usuario auth:", auth_resp.text)
    exit()

auth_user_id = auth_resp.json()["id"]
print("Auth user creado:", auth_user_id)

# 2️⃣ Insertar en tabla public.users
db_resp = requests.post(
    f"{SUPABASE_URL}/rest/v1/users",
    headers={
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    },
    json={
        "auth_id": auth_user_id,
        "email": email,
        "name": name,
        "rol": "admin",
        "categoria": 0,
    },
)

if db_resp.status_code not in (200, 201):
    print("Error insertando en tabla users:", db_resp.text)
else:
    print("Admin creado correctamente 🔥")
