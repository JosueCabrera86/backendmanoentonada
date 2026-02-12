from flask import Flask, jsonify, request
from flask_cors import CORS
from functools import wraps
import os
import requests
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

CORS(
    app,
    resources={r"/*": {"origins": [
        "https://manoentonada.com",
        "https://www.manoentonada.com",
        "http://localhost:5173"
    ]}},
    supports_credentials=True
)


SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")



def token_required(required_rol=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"message": "Token no enviado"}), 403

            token = auth_header.split(" ")[1]

           
            auth_resp = requests.get(
                f"{SUPABASE_URL}/auth/v1/user",
                headers={
                    "apikey": SUPABASE_ANON_KEY,
                    "Authorization": f"Bearer {token}",
                },
            )

            if auth_resp.status_code != 200:
                return jsonify({"message": "Token inválido"}), 401

            auth_user = auth_resp.json()
            auth_id = auth_user["id"]  

            print("=== DEBUG TOKEN HEADER ===")
            print("auth_header:", auth_header)
            print("AUTH_ID:", auth_id)
            print("USER EMAIL:", auth_user.get("email"))

            
            db_resp = requests.get(
                f"{SUPABASE_URL}/rest/v1/users?auth_id=eq.{auth_id}&select=rol",
                headers={
                    "apikey": SUPABASE_SERVICE_KEY,
                    "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
                },
            )

            print("=== DEBUG DB RESPONSE ===")
            print("Status code:", db_resp.status_code)
            try:
                print("Response JSON:", db_resp.json())
            except Exception as e:
                print("No JSON response:", db_resp.text)

            if not db_resp.ok or not db_resp.json():
                return jsonify({"message": "Usuario no registrado en la base"}), 403

            rol = db_resp.json()[0]["rol"]

            if required_rol and rol != required_rol:
                return jsonify({"message": "Permiso denegado"}), 403

            kwargs["current_user"] = {
                "auth_id": auth_id,
                "rol": rol,
                "email": auth_user.get("email"),
            }

            return f(*args, **kwargs)

        return decorated
    return decorator





@app.route("/admin/users", methods=["GET"])
@token_required(required_rol="admin")
def get_users(current_user):
    try:
        url = f"{SUPABASE_URL}/rest/v1/users?select=id,auth_id,name,email,rol,categoria,disciplina"

        headers = {
            "apikey": SUPABASE_SERVICE_KEY,
            "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        }

        print("=== DEBUG GET USERS ===")
        print("URL:", url)
        print("HEADERS:", headers)

        resp = requests.get(url, headers=headers)

        print("Status code:", resp.status_code)
        try:
            print("Response JSON:", resp.json())
        except Exception as e:
            print("No JSON response, raw text:", resp.text)

        if not resp.ok:
            return jsonify({"error": "Error en Supabase", "details": resp.text}), resp.status_code

        return jsonify(resp.json()), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": "internal", "details": str(e)}), 500

@app.route("/users", methods=["POST"])
@token_required(required_rol="admin")
def create_user(current_user):
    try:
        data = request.get_json()

        email = data.get("email")
        password = data.get("password")
        rol = data.get("rol")
        name = data.get("name")
        categoria = data.get("categoria")
        

        # Validaciones obligatorias
        missing_fields = [
            field_name for field_name, value in [
                ("email", email), ("password", password),
                ("rol", rol), ("name", name),
                ("categoria", categoria)
            ] if not value
        ]
        if missing_fields:
            return jsonify({"error": f"Faltan campos obligatorios: {', '.join(missing_fields)}"}), 400

        # Forzar categoria a int
        try:
            categoria = int(categoria)
        except Exception:
            return jsonify({"error": "Categoria debe ser un número válido"}), 400


        auth_payload = {
             "email": email,
             "password": password,
             "email_confirm": True,
             "user_metadata": {
                "rol": rol,
                "name": name,
                "categoria": categoria,
                
            },
        }

        auth_resp = requests.post(
            f"{SUPABASE_URL}/auth/v1/admin/users",
            headers={
                "apikey": SUPABASE_SERVICE_KEY,
                "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
                "Content-Type": "application/json",
            },
            json=auth_payload
        )

        if auth_resp.status_code not in (200, 201):
            try:
                return jsonify({"error": auth_resp.json()}), auth_resp.status_code
            except:
                return jsonify({"error": auth_resp.text}), auth_resp.status_code

        auth_user_id = auth_resp.json()["id"]

        # 2️⃣ Insertar en tabla public.users
        user_insert_payload = {
            "auth_id": auth_user_id,
            "email": email,
            "name": name,
            "rol": rol,
            "categoria": categoria,
        
        }

        user_insert_resp = requests.post(
            f"{SUPABASE_URL}/rest/v1/users?on_conflict=auth_id",
            headers={
                "apikey": SUPABASE_SERVICE_KEY,
                "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
                "Content-Type": "application/json",
            },
            json=user_insert_payload
        )

        if user_insert_resp.status_code not in (200, 201):
            try:
                return jsonify({"error": user_insert_resp.json()}), user_insert_resp.status_code
            except:
                return jsonify({"error": user_insert_resp.text}), user_insert_resp.status_code

        return jsonify({"message": "Usuario creado correctamente", "auth_id": auth_user_id}), 201

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": "internal", "details": str(e)}), 500

@app.route("/users", methods=["PATCH"])
@token_required(required_rol="admin")
def edit_user(current_user):
    data = request.get_json()
    user_id = data.get("id")

    if not user_id:
        return jsonify({"error": "ID requerido"}), 400

    # ------------------ 1️⃣ UPDATE AUTH (PASSWORD) ------------------
    if "password" in data and data["password"]:
        auth_resp = requests.put(
            f"{SUPABASE_URL}/auth/v1/admin/users/{user_id}",
            headers={
                "apikey": SUPABASE_SERVICE_KEY,
                "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "password": data["password"]
            },
        )

        if auth_resp.status_code not in (200, 204):
            return jsonify({
                "error": "Error actualizando contraseña",
                "details": auth_resp.text
            }), auth_resp.status_code

    # ------------------ 2️⃣ UPDATE PERFIL ------------------
    updates = {}
    for field in ["name", "rol", "categoria"]:
        if field in data:
            updates[field] = data[field]

    if updates:
        resp = requests.patch(
            f"{SUPABASE_URL}/rest/v1/users?auth_id=eq.{user_id}",
            headers={
                "apikey": SUPABASE_SERVICE_KEY,
                "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
                "Content-Type": "application/json",
            },
            json=updates,
        )

        if not resp.ok:
            return jsonify({"error": resp.json()}), resp.status_code

    return jsonify({"message": "Usuario actualizado"}), 200



@app.route("/users/multiple", methods=["PATCH"])
@token_required(required_rol="admin")
def edit_multiple_users(current_user):
    data = request.get_json()
    ids = data.get("ids", [])
    categoria = data.get("categoria")

    if not ids or categoria is None:
        return jsonify({"error": "Faltan datos"}), 400

    for uid in ids:
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/users?auth_id=eq.{uid}",
            headers={
                "apikey": SUPABASE_SERVICE_KEY,
                "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
                "Content-Type": "application/json",
            },
            json={"categoria": int(categoria)},
        )

    return jsonify({"message": "Usuarios actualizados"}), 200



@app.route("/users/<user_id>", methods=["DELETE"])
@token_required(required_rol="admin")
def delete_user(current_user, user_id):
    try:
        # 1️⃣ borrar perfil
        resp = requests.delete(
            f"{SUPABASE_URL}/rest/v1/users?auth_id=eq.{user_id}",
            headers={
                "apikey": SUPABASE_SERVICE_KEY,
                "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
            },
        )

        if resp.status_code not in (200, 204):
            return jsonify({
                "error": "Error borrando usuario en base",
                "details": resp.text
            }), resp.status_code

        # 2️⃣ borrar auth
        delete_auth = requests.delete(
            f"{SUPABASE_URL}/auth/v1/admin/users/{user_id}",
            headers={
                "apikey": SUPABASE_SERVICE_KEY,
                "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
            },
        )

        if delete_auth.status_code not in (200, 204):
            return jsonify({
                "error": "Error borrando usuario en auth",
                "details": delete_auth.text
            }), delete_auth.status_code

        return jsonify({
            "message": "Usuario eliminado correctamente"
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": "Error interno",
            "details": str(e)
        }), 500

