import base64
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Literal, Optional

import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
import uvicorn
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "server.log")
ENV_FILE = os.path.join(BASE_DIR, ".env")
STATIC_DIR = os.path.join(BASE_DIR, "static")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()]
)
logger = logging.getLogger("POS")
logging.getLogger("uvicorn.access").handlers = []
logging.getLogger("uvicorn.access").propagate = False

load_dotenv(ENV_FILE, override=True)

APP_NAME = "SecureVault POS System"
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "").strip()
MASTER_KEY = os.environ.get("SERVER_MASTER_KEY", "").strip() or Fernet.generate_key().decode()

MAX_ATTEMPTS = 5
LOCK_SECONDS = 60
SESSION_TTL = 8 * 3600
INVITE_TTL = 24 * 3600
MIN_PASSWORD = 8
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode())

def hash_secret(secret: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    h = hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt${b64e(salt)}${b64e(h)}"

def verify_secret(secret: str, stored: str) -> bool:
    try:
        _, s, h = stored.split("$")
        cand = hashlib.scrypt(secret.encode("utf-8"), salt=b64d(s), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(cand, b64d(h))
    except Exception:
        return False

DUMMY_HASH = hash_secret("dummy-password")

def compute_integrity_hmac(payload_dict: dict) -> str:
    canonical = json.dumps(payload_dict, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hmac.new(MASTER_KEY.encode("utf-8"), canonical, hashlib.sha256).hexdigest()

def norm_code(code: str) -> str:
    return code.strip().upper().replace("-", "")

def new_recovery_code() -> str:
    return "-".join(secrets.token_hex(2).upper() for _ in range(3))

def normalize(username: str) -> str:
    return username.strip().lower()

def unit_price(price: float, discount: int) -> float:
    return round(float(price) * (1 - int(discount) / 100), 2)


class PostgresDB:
    def __init__(self, dsn: str):
        if not dsn:
            raise RuntimeError("Не задан DATABASE_URL в переменных окружения!")
        self.dsn = dsn
        self.lock = threading.RLock()
        self._fernet = Fernet(MASTER_KEY.encode())
        self.conn = psycopg2.connect(self.dsn, cursor_factory=RealDictCursor)
        self.conn.autocommit = True

    def execute(self, query: str, params: tuple = (), fetch: str = "none"):
        with self.lock:
            if self.conn.closed:
                self.conn = psycopg2.connect(self.dsn, cursor_factory=RealDictCursor)
                self.conn.autocommit = True
            with self.conn.cursor() as cur:
                cur.execute(query, params)
                if fetch == "one":
                    row = cur.fetchone()
                    return dict(row) if row else None
                if fetch == "all":
                    return [dict(r) for r in cur.fetchall()]
                return None

    def enc(self, text: str) -> str:
        return self._fernet.encrypt(text.encode()).decode()

    def chat_id(self, tg_enc: str):
        if not tg_enc:
            return None
        try:
            return int(self._fernet.decrypt(tg_enc.encode()).decode())
        except Exception:
            return None


db = PostgresDB(DATABASE_URL)

sessions: dict[str, dict] = {}
invites: dict[str, float] = {}

def purge():
    now = time.time()
    for k in [k for k, v in sessions.items() if v["expires"] < now]:
        sessions.pop(k, None)
    for k in [k for k, v in invites.items() if v < now]:
        invites.pop(k, None)

def drop_sessions(name: str):
    for t in [t for t, s in sessions.items() if s["name"] == name]:
        sessions.pop(t, None)

def start_session(name: str) -> dict:
    token = secrets.token_urlsafe(32)
    sessions[token] = {"name": name, "expires": time.time() + SESSION_TTL}
    rec = db.execute("SELECT role, google_email FROM users WHERE username = %s", (name,), "one")
    logger.info(f"[АУДИТ] Создана веб-сессия для '{name}' (Роль: {rec['role']})")
    return {"token": token, "username": name, "role": rec["role"], "google_email": rec.get("google_email") or ""}

def current_user(authorization: str = Header(default="")):
    token = authorization.removeprefix("Bearer ").strip()
    s = sessions.get(token)
    if not s or s["expires"] < time.time():
        sessions.pop(token, None)
        raise HTTPException(401, "Сессия истекла. Войдите заново.")
    rec = db.execute("SELECT * FROM users WHERE username = %s", (s["name"],), "one")
    if not rec:
        sessions.pop(token, None)
        raise HTTPException(401, "Учётная запись не найдена.")
    return {"name": s["name"], "role": rec["role"], "rec": rec, "token": token}

def require_manager(u=Depends(current_user)):
    if u["role"] not in ("admin", "manager"):
        raise HTTPException(403, "Недостаточно прав.")
    return u

def require_admin(u=Depends(current_user)):
    if u["role"] != "admin":
        raise HTTPException(403, "Только для администратора.")
    return u


class LoginIn(BaseModel):
    username: str
    password: str

class RegisterIn(BaseModel):
    username: str
    password: str
    invite_code: str = ""

class MenuIn(BaseModel):
    name: str
    category: str = "Прочее"
    ingredients: str = "Стандартный рецепт"
    price: float = Field(gt=0)
    stock: int = Field(ge=0)

class DiscountIn(BaseModel):
    discount: int = Field(ge=0, le=100)

class StockIn(BaseModel):
    stock: int = Field(ge=0)

class OrderLineIn(BaseModel):
    id: int
    qty: int = Field(ge=1)

class OrderIn(BaseModel):
    table: str = ""
    type: Literal["В заведении", "На вынос"] = "В заведении"
    payment: Literal["Карта", "Наличные"] = "Карта"
    items: list[OrderLineIn] = Field(min_length=1)

class StatusIn(BaseModel):
    status: Literal["Новый", "Готовится", "Выполнен", "Отменен"]

class RoleIn(BaseModel):
    role: Literal["user", "manager"]


app = FastAPI(title=APP_NAME)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/api/health")
def health():
    return {"status": "ok", "db": "PostgreSQL (Supabase)"}


@app.post("/api/auth/login")
def login(b: LoginIn):
    name = normalize(b.username)
    purge()
    rec = db.execute("SELECT * FROM users WHERE username = %s", (name,), "one")
    if not rec:
        verify_secret(b.password, DUMMY_HASH)
        logger.warning(f"[АУДИТ ОШИБКА] Попытка входа несуществующего логина: '{name}'")
        raise HTTPException(401, "Неверный логин или пароль.")

    if rec["locked_until"] > time.time():
        raise HTTPException(429, f"Аккаунт временно заблокирован. Подождите {int(rec['locked_until'] - time.time()) + 1} сек.")

    if not verify_secret(b.password, rec["pw_hash"]):
        failed = rec["failed"] + 1
        locked = time.time() + LOCK_SECONDS if failed >= MAX_ATTEMPTS else 0
        db.execute("UPDATE users SET failed = %s, locked_until = %s WHERE username = %s", (0 if locked else failed, locked, name))
        logger.warning(f"[АУДИТ ОШИБКА] Неверный пароль для '{name}'")
        raise HTTPException(401, "Неверный логин или пароль.")

    db.execute("UPDATE users SET failed = 0 WHERE username = %s", (name,))
    return start_session(name)


@app.post("/api/auth/register")
def register(b: RegisterIn):
    name = normalize(b.username)
    if not USERNAME_RE.match(name):
        raise HTTPException(400, "Логин: 3–32 символа, латиница, цифры, _ . -")
    if len(b.password) < MIN_PASSWORD:
        raise HTTPException(400, f"Пароль должен быть не короче {MIN_PASSWORD} символов.")
    if db.execute("SELECT 1 FROM users WHERE username = %s", (name,), "one"):
        raise HTTPException(400, "Этот логин уже занят.")

    has_admin = db.execute("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1", (), "one") is not None
    if has_admin and b.invite_code.strip():
        exp = invites.get(norm_code(b.invite_code))
        if not exp or exp < time.time():
            raise HTTPException(403, "Неверный или просроченный код приглашения.")
        invites.pop(norm_code(b.invite_code), None)
        role = "user"
    elif has_admin and not b.invite_code.strip():
        raise HTTPException(403, "Введите код приглашения от администратора.")
    else:
        role = "admin"

    rec_code = new_recovery_code()
    db.execute(
        "INSERT INTO users (username, role, pw_hash, rec_hash) VALUES (%s, %s, %s, %s)",
        (name, role, hash_secret(b.password), hash_secret(norm_code(rec_code)))
    )
    logger.info(f"[РЕГИСТРАЦИЯ] Зарегистрирован сотрудник '{name}' (Роль: {role})")
    return {"recovery_code": rec_code, "role": role}


@app.post("/api/auth/logout")
def logout(u=Depends(current_user)):
    sessions.pop(u["token"], None)
    logger.info(f"[АУДИТ] Пользователь '{u['name']}' вышел из системы")
    return {"status": "ok"}


@app.get("/api/menu")
def get_menu(u=Depends(current_user)):
    rows = db.execute("SELECT * FROM menu ORDER BY id", (), "all")
    for r in rows:
        r["price"] = float(r["price"])
    return rows

@app.post("/api/menu")
def add_menu(b: MenuIn, u=Depends(require_manager)):
    row = db.execute(
        "INSERT INTO menu (name, category, ingredients, price, discount, stock) VALUES (%s, %s, %s, %s, 0, %s) RETURNING *",
        (b.name.strip(), b.category.strip(), b.ingredients.strip(), b.price, b.stock), "one"
    )
    logger.info(f"[МЕНЮ] '{u['name']}' добавил блюдо '{b.name}' ({b.price} тг)")
    return row

@app.patch("/api/menu/{item_id}/discount")
def set_discount(item_id: int, b: DiscountIn, u=Depends(require_manager)):
    db.execute("UPDATE menu SET discount = %s WHERE id = %s", (b.discount, item_id))
    logger.info(f"[МЕНЮ] '{u['name']}' установил скидку {b.discount}% на ID #{item_id}")
    return {"status": "ok"}

@app.patch("/api/menu/{item_id}/stock")
def set_stock(item_id: int, b: StockIn, u=Depends(require_manager)):
    db.execute("UPDATE menu SET stock = %s WHERE id = %s", (b.stock, item_id))
    logger.info(f"[СКЛАД] '{u['name']}' обновил остаток ID #{item_id} до {b.stock}")
    return {"status": "ok"}

@app.delete("/api/menu/{item_id}")
def delete_menu(item_id: int, u=Depends(require_manager)):
    db.execute("DELETE FROM menu WHERE id = %s", (item_id,))
    logger.warning(f"[МЕНЮ] '{u['name']}' удалил позицию ID #{item_id}")
    return {"status": "ok"}


@app.get("/api/orders")
def get_orders(u=Depends(current_user)):
    rows = db.execute("SELECT * FROM orders ORDER BY id DESC", (), "all")
    for r in rows:
        r["table"] = r.pop("table_name")
        r["total"] = float(r["total"])
        r["created_at"] = r["created_at"].strftime("%Y-%m-%d %H:%M") if hasattr(r["created_at"], "strftime") else str(r["created_at"])[:16]
    return rows

@app.post("/api/orders")
def create_order(b: OrderIn, u=Depends(current_user)):
    merged: dict[int, int] = {}
    for ln in b.items:
        merged[ln.id] = merged.get(ln.id, 0) + ln.qty

    lines, total = [], 0.0
    for iid, q in merged.items():
        row = db.execute("SELECT * FROM menu WHERE id = %s", (iid,), "one")
        if not row:
            raise HTTPException(400, "Позиция не найдена в меню.")
        if row["stock"] < q:
            raise HTTPException(409, f"Недостаточно «{row['name']}» на складе (остаток: {row['stock']}).")
        pr = unit_price(row["price"], row["discount"])
        total += pr * q
        lines.append({"id": iid, "name": row["name"], "qty": q, "price": pr})

    table_name = b.table.strip() or ("На вынос" if b.type == "На вынос" else "Стол №1")
    summary = ", ".join(f"{l['name']} x{l['qty']}" for l in lines)
    total = round(total, 2)

    for l in lines:
        db.execute("UPDATE menu SET stock = stock - %s WHERE id = %s", (l["qty"], l["id"]))

    order = db.execute(
        "INSERT INTO orders (table_name, type, items, total, payment, status, waiter) VALUES (%s, %s, %s, %s, %s, 'Новый', %s) RETURNING id",
        (table_name, b.type, summary, total, b.payment, u["name"]), "one"
    )
    oid = order["id"]
    for l in lines:
        db.execute(
            "INSERT INTO order_items (order_id, menu_item_id, name, qty, price) VALUES (%s, %s, %s, %s, %s)",
            (oid, l["id"], l["name"], l["qty"], l["price"])
        )

    logger.info(f"[КАССА] Кассир '{u['name']}' оформил заказ #{oid} на {total} тг ({b.payment})")
    return {"id": oid, "total": total}

@app.patch("/api/orders/{order_id}/status")
def update_order_status(order_id: int, b: StatusIn, u=Depends(current_user)):
    row = db.execute("SELECT status FROM orders WHERE id = %s", (order_id,), "one")
    if not row:
        raise HTTPException(404, "Заказ не найден.")
    if row["status"] == "Отменен":
        raise HTTPException(409, "Отменённый заказ изменить нельзя.")
    if b.status == "Отменен":
        items = db.execute("SELECT menu_item_id, qty FROM order_items WHERE order_id = %s", (order_id,), "all")
        for it in items:
            db.execute("UPDATE menu SET stock = stock + %s WHERE id = %s", (it["qty"], it["menu_item_id"]))
    db.execute("UPDATE orders SET status = %s WHERE id = %s", (b.status, order_id))
    logger.info(f"[ЗАКАЗ] Статус заказа #{order_id} изменён на '{b.status}' ({u['name']})")
    return {"status": "ok"}

@app.delete("/api/orders/{order_id}")
def delete_order(order_id: int, u=Depends(require_manager)):
    row = db.execute("SELECT status FROM orders WHERE id = %s", (order_id,), "one")
    if row and row["status"] in ("Новый", "Готовится"):
        items = db.execute("SELECT menu_item_id, qty FROM order_items WHERE order_id = %s", (order_id,), "all")
        for it in items:
            db.execute("UPDATE menu SET stock = stock + %s WHERE id = %s", (it["qty"], it["menu_item_id"]))
    db.execute("DELETE FROM orders WHERE id = %s", (order_id,))
    logger.warning(f"[ЗАКАЗ] Менеджер '{u['name']}' удалил заказ #{order_id}")
    return {"status": "ok"}


@app.get("/api/admin/users")
def list_users(u=Depends(require_admin)):
    rows = db.execute("SELECT username, role, tg_enc, google_email FROM users ORDER BY created_at", (), "all")
    return [{"login": r["username"], "role": r["role"], "tg": bool(r["tg_enc"]), "google_email": r["google_email"] or ""} for r in rows]

@app.patch("/api/admin/users/{name}/role")
def set_role(name: str, b: RoleIn, u=Depends(require_admin)):
    n = normalize(name)
    rec = db.execute("SELECT role FROM users WHERE username = %s", (n,), "one")
    if not rec:
        raise HTTPException(404, "Сотрудник не найден.")
    if rec["role"] == "admin":
        raise HTTPException(409, "Роль администратора изменять нельзя.")
    db.execute("UPDATE users SET role = %s WHERE username = %s", (b.role, n))
    logger.warning(f"[БЕЗОПАСНОСТЬ] Админ '{u['name']}' изменил роль '{n}' на '{b.role}'")
    return {"status": "ok"}

@app.delete("/api/admin/users/{name}")
def delete_user(name: str, u=Depends(require_admin)):
    n = normalize(name)
    rec = db.execute("SELECT role FROM users WHERE username = %s", (n,), "one")
    if not rec or rec["role"] == "admin" or n == u["name"]:
        raise HTTPException(409, "Нельзя удалить администратора или самого себя.")
    db.execute("DELETE FROM users WHERE username = %s", (n,))
    drop_sessions(n)
    logger.warning(f"[БЕЗОПАСНОСТЬ] Админ '{u['name']}' удалил сотрудника '{n}'")
    return {"status": "ok"}

@app.post("/api/admin/invites")
def make_invite(u=Depends(require_admin)):
    purge()
    code = new_recovery_code()
    invites[norm_code(code)] = time.time() + INVITE_TTL
    logger.info(f"[БЕЗОПАСНОСТЬ] Админ '{u['name']}' сгенерировал инвайт-код")
    return {"code": code}


@app.get("/api/admin/logs")
def get_logs(start_time: Optional[str] = None, end_time: Optional[str] = None, u=Depends(require_admin)):
    if not os.path.exists(LOG_FILE):
        return {"logs": []}
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip()]

    s_raw = start_time.strip() if start_time else ""
    e_raw = end_time.strip() if end_time else ""
    filtered = []
    for line in lines:
        log_dt = line[:19]
        if len(log_dt) < 19 or log_dt[10] != " ":
            continue
        log_date, log_time = log_dt[:10], log_dt[11:19]
        if s_raw:
            if " " in s_raw and log_dt < s_raw: continue
            elif "-" in s_raw and " " not in s_raw and log_date < s_raw: continue
            elif ":" in s_raw and " " not in s_raw and log_time < (s_raw if s_raw.count(":") == 2 else f"{s_raw}:00"): continue
        if e_raw:
            if " " in e_raw and log_dt > e_raw: continue
            elif "-" in e_raw and " " not in e_raw and log_date > e_raw: continue
            elif ":" in e_raw and " " not in e_raw and log_time > (e_raw if e_raw.count(":") == 2 else f"{e_raw}:59"): continue
        filtered.append(line)
    return {"logs": filtered[-1000:]}


@app.get("/api/admin/backup/json")
def export_json(u=Depends(require_admin)):
    users = db.execute("SELECT username, role, pw_hash, rec_hash, tg_enc, google_sub, google_email FROM users", (), "all")
    menu = db.execute("SELECT id, name, category, ingredients, price::float, discount, stock FROM menu ORDER BY id", (), "all")
    orders = db.execute("SELECT id, table_name, type, items, total::float, payment, status, waiter, created_at::text FROM orders ORDER BY id", (), "all")
    data_block = {"users": users, "menu": menu, "orders": orders}
    snapshot = {
        "version": 3,
        "engine": "PostgreSQL (Supabase)",
        "exported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "integrity_hmac_sha256": compute_integrity_hmac(data_block),
        "data": data_block
    }
    logger.info(f"[БЭКАП] Админ '{u['name']}' выгрузил подписанный JSON-снимок БД")
    raw = json.dumps(snapshot, ensure_ascii=False, indent=2).encode("utf-8")
    return StreamingResponse(io.BytesIO(raw), media_type="application/json",
                             headers={"Content-Disposition": "attachment; filename=SecureVault_SignedBackup.json"})

@app.post("/api/admin/restore/json")
async def restore_json(request: Request, u=Depends(require_admin)):
    snapshot = await request.json()
    data_block = snapshot.get("data")
    sig = snapshot.get("integrity_hmac_sha256", "")
    if not data_block or not sig:
        raise HTTPException(400, "Неверный формат файла бэкапа или отсутствует подпись целостности.")

    expected_sig = compute_integrity_hmac(data_block)
    if not hmac.compare_digest(sig, expected_sig):
        logger.error(f"[ЦЕЛОСТНОСТЬ НАРУШЕНА] Админ '{u['name']}' попытался загрузить изменённый файл бэкапа!")
        raise HTTPException(400, "ОШИБКА ЦЕЛОСТНОСТИ: Контрольная сумма HMAC-SHA256 не совпадает! Файл был модифицирован.")

    db.execute("DELETE FROM order_items")
    db.execute("DELETE FROM orders")
    db.execute("DELETE FROM menu")
    db.execute("DELETE FROM users")

    for r in data_block["users"]:
        db.execute(
            "INSERT INTO users (username, role, pw_hash, rec_hash, tg_enc, google_sub, google_email) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (r["username"], r["role"], r["pw_hash"], r["rec_hash"], r.get("tg_enc", ""), r.get("google_sub"), r.get("google_email"))
        )
    for m in data_block["menu"]:
        db.execute(
            "INSERT INTO menu (id, name, category, ingredients, price, discount, stock) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (m["id"], m["name"], m["category"], m["ingredients"], m["price"], m["discount"], m["stock"])
        )
    for o in data_block["orders"]:
        db.execute(
            "INSERT INTO orders (id, table_name, type, items, total, payment, status, waiter, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (o["id"], o["table_name"], o["type"], o["items"], o["total"], o["payment"], o["status"], o["waiter"], o["created_at"])
        )
    logger.warning(f"[ВОССТАНОВЛЕНИЕ] БД успешно восстановлена из проверенного бэкапа ({u['name']})")
    return {"status": "ok"}

@app.get("/api/admin/backup/excel")
def export_excel(u=Depends(require_admin)):
    output = io.BytesIO()
    df_orders = pd.read_sql_query("SELECT id, table_name AS Стол, type AS Тип, items AS Состав, total AS Сумма, payment AS Оплата, status AS Статус, waiter AS Кассир FROM orders", db.conn)
    df_menu = pd.read_sql_query("SELECT id, name AS Блюдо, category AS Категория, price AS Цена, discount AS Скидка, stock AS Остаток FROM menu", db.conn)
    df_users = pd.read_sql_query("SELECT username AS Логин, role AS Роль, google_email AS Google FROM users", db.conn)
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df_orders.to_excel(writer, sheet_name="Заказы", index=False)
        df_menu.to_excel(writer, sheet_name="Меню", index=False)
        df_users.to_excel(writer, sheet_name="Сотрудники", index=False)
    output.seek(0)
    return StreamingResponse(output, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                             headers={"Content-Disposition": "attachment; filename=SecureVault_Report.xlsx"})


if os.path.exists(STATIC_DIR):
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")

if __name__ == "__main__":
    logger.info("Запуск облачного веб-сервера SecureVault POS (PostgreSQL)...")
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
