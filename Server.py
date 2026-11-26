import asyncio
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
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

import pandas as pd
import psycopg2
from psycopg2 import sql
from psycopg2.extras import RealDictCursor
import uvicorn
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
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

APP_NAME = "Гурман POS System"
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "").strip()
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
CONFIGURED_MASTER_KEY = os.environ.get("SERVER_MASTER_KEY", "").strip()
MASTER_KEY = CONFIGURED_MASTER_KEY or Fernet.generate_key().decode()

MAX_ATTEMPTS = 5
LOCK_SECONDS = 60
CODE_TTL = 300
CODE_TRIES = 3
LINK_TTL = 600
SESSION_TTL = 8 * 3600
INVITE_TTL = 24 * 3600
MIN_PASSWORD = 8
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

DEFAULT_CATEGORIES = [
    ("Первые блюда", 1, "#E8B65C"),
    ("Вторые блюда", 2, "#F0707A"),
    ("Гарниры", 3, "#D9C36A"),
    ("Салаты", 4, "#6FD3A0"),
    ("Десерты", 5, "#E28AD4"),
    ("Напитки", 6, "#6BA8F2"),
]

DEFAULT_TABLES = [
    ("Стол №1", 4, "Основной зал", "free"),
    ("Стол №2", 4, "Основной зал", "free"),
    ("Стол №3", 2, "Основной зал", "free"),
    ("Стол №4", 6, "Терраса", "free"),
    ("На вынос", 1, "Стойка выдачи", "free"),
]


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

def _canonicalize_numbers(obj):
    if isinstance(obj, float):
        return int(obj) if obj.is_integer() else round(obj, 6)
    if isinstance(obj, dict):
        return {k: _canonicalize_numbers(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_canonicalize_numbers(v) for v in obj]
    return obj

def compute_integrity_hmac(payload_dict: dict) -> str:
    normalized = _canonicalize_numbers(payload_dict)
    canonical = json.dumps(normalized, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hmac.new(MASTER_KEY.encode("utf-8"), canonical, hashlib.sha256).hexdigest()

def norm_code(code: str) -> str:
    return code.strip().upper().replace("-", "")

def new_recovery_code() -> str:
    return "-".join(secrets.token_hex(2).upper() for _ in range(3))

def normalize(username: str) -> str:
    return username.strip().lower()

def unit_price(price: float, discount: int) -> float:
    return round(float(price) * (1 - int(discount) / 100), 2)

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class PostgresDB:
    def __init__(self, dsn: str):
        if not dsn:
            raise RuntimeError("Не задан DATABASE_URL в переменных окружения.")
        self.dsn = dsn
        self.lock = threading.RLock()
        self._fernet = Fernet(MASTER_KEY.encode())
        self.conn = psycopg2.connect(self.dsn, cursor_factory=RealDictCursor)
        self.conn.autocommit = True

    def _connect_if_closed(self):
        if self.conn.closed:
            self.conn = psycopg2.connect(self.dsn, cursor_factory=RealDictCursor)
            self.conn.autocommit = True

    @contextmanager
    def transaction(self, *, readonly: bool = False):
        with self.lock:
            self._connect_if_closed()
            self.conn.autocommit = False
            try:
                with self.conn:
                    if readonly:
                        self.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                    yield
            finally:
                if not self.conn.closed:
                    self.conn.autocommit = True

    def execute(self, query, params: tuple = (), fetch: str = "none"):
        with self.lock:
            self._connect_if_closed()
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

    def dec(self, token_text: str) -> str:
        return self._fernet.decrypt(token_text.encode()).decode()

    def chat_id(self, tg_enc: str):
        if not tg_enc:
            return None
        try:
            return int(self._fernet.decrypt(tg_enc.encode()).decode())
        except Exception:
            return None


class DBAuditHandler(logging.Handler):
    def __init__(self, database: PostgresDB):
        super().__init__()
        self._db = database
        self._writing = False

    def emit(self, record: logging.LogRecord):
        if self._writing or record.name.startswith("uvicorn"):
            return
        try:
            self._writing = True
            msg = record.getMessage()
            cat_match = re.match(r"^\[([^\]]+)\]\s*", msg)
            category = cat_match.group(1) if cat_match else "АУДИТ"
            actor_match = re.search(r"'([A-Za-z0-9_.-]{3,32})'", msg)
            cand_actor = actor_match.group(1) if actor_match else None
            actor = None
            if cand_actor:
                exists = self._db.execute("SELECT 1 FROM users WHERE username = %s", (cand_actor.lower(),), "one")
                if exists:
                    actor = cand_actor.lower()
            ts = datetime.fromtimestamp(record.created, tz=timezone.utc)
            self._db.execute(
                "INSERT INTO audit_logs (created_at, level, actor, category, message) VALUES (%s, %s, %s, %s, %s)",
                (ts, record.levelname.ljust(7), actor, category[:64], msg),
            )
        except Exception:
            pass
        finally:
            self._writing = False


db = PostgresDB(DATABASE_URL)
logger.addHandler(DBAuditHandler(db))

sessions: dict[str, dict] = {}
challenges: dict[str, dict] = {}
link_tokens: dict[str, dict] = {}
oauth_states: dict[str, dict] = {}
tg_offset = 0
bot_username = ""


def seed_reference_tables():
    for name, sort_order, color in DEFAULT_CATEGORIES:
        db.execute(
            "INSERT INTO categories (name, sort_order, color) VALUES (%s, %s, %s) ON CONFLICT (name) DO NOTHING",
            (name, sort_order, color),
        )
    for label, seats, zone, status in DEFAULT_TABLES:
        db.execute(
            "INSERT INTO dining_tables (label, seats, zone, status) VALUES (%s, %s, %s, %s) ON CONFLICT (label) DO NOTHING",
            (label, seats, zone, status),
        )
    db.execute(
        """
        UPDATE menu m
        SET category_id = c.id
        FROM categories c
        WHERE m.category = c.name AND m.category_id IS DISTINCT FROM c.id
        """
    )
    db.execute(
        """
        UPDATE orders o
        SET table_id = t.id
        FROM dining_tables t
        WHERE o.table_name = t.label AND o.table_id IS DISTINCT FROM t.id
        """
    )


def ensure_category(name: str) -> int:
    clean = (name or "Прочее").strip()
    row = db.execute("SELECT id FROM categories WHERE name = %s", (clean,), "one")
    if row:
        return row["id"]
    created = db.execute(
        "INSERT INTO categories (name, sort_order, color) VALUES (%s, 99, '#B9A4F5') ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
        (clean,),
        "one",
    )
    return created["id"]


def ensure_table(label: str, order_type: str = "В заведении") -> int:
    clean = (label or "").strip() or ("На вынос" if order_type == "На вынос" else "Стол №1")
    row = db.execute("SELECT id FROM dining_tables WHERE label = %s", (clean,), "one")
    if row:
        return row["id"]
    created = db.execute(
        "INSERT INTO dining_tables (label, seats, zone, status) VALUES (%s, 4, 'Основной зал', 'free') ON CONFLICT (label) DO UPDATE SET label = EXCLUDED.label RETURNING id",
        (clean,),
        "one",
    )
    return created["id"]


def record_stock_movement(menu_item_id: int, delta: int, reason: str, actor: Optional[str]):
    valid_actor = actor if actor and db.execute("SELECT 1 FROM users WHERE username = %s", (actor,), "one") else None
    db.execute(
        "INSERT INTO stock_movements (menu_item_id, delta, reason, actor) VALUES (%s, %s, %s, %s)",
        (menu_item_id, delta, reason, valid_actor),
    )


def record_order_status_history(order_id: int, old_status: str, new_status: str, changed_by: Optional[str]):
    valid_actor = changed_by if changed_by and db.execute("SELECT 1 FROM users WHERE username = %s", (changed_by,), "one") else None
    db.execute(
        "INSERT INTO order_status_history (order_id, old_status, new_status, changed_by) VALUES (%s, %s, %s, %s)",
        (order_id, old_status, new_status, valid_actor),
    )


def validate_invite_code(raw_code: str) -> Optional[int]:
    clean = norm_code(raw_code)
    if not clean:
        return None
    now = utc_now()
    rows = db.execute(
        "SELECT id, code_hash FROM invite_codes WHERE used_at IS NULL AND (expires_at IS NULL OR expires_at > %s)",
        (now,),
        "all",
    )
    for r in rows:
        if verify_secret(clean, r["code_hash"]):
            return r["id"]
    return None


def mark_invite_used(invite_id: int, username: str):
    now = utc_now()
    db.execute(
        "UPDATE invite_codes SET used_by = %s, used_at = %s WHERE id = %s AND used_at IS NULL",
        (username, now, invite_id),
    )


def consume_invite_code(raw_code: str, username: str) -> bool:
    inv_id = validate_invite_code(raw_code)
    if inv_id is None:
        return False
    now = utc_now()
    updated = db.execute(
        "UPDATE invite_codes SET used_by = %s, used_at = %s WHERE id = %s AND used_at IS NULL RETURNING id",
        (username, now, inv_id),
        "one",
    )
    return bool(updated)


def purge():
    now = time.time()
    for store in (sessions, challenges, link_tokens, oauth_states):
        for k in [k for k, v in store.items() if v["expires"] < now]:
            store.pop(k, None)

def drop_sessions(name: str):
    for t in [t for t, s in sessions.items() if s["name"] == name]:
        sessions.pop(t, None)

def tg_call(method: str, params: dict | None = None):
    if not TG_BOT_TOKEN:
        raise RuntimeError("TG_BOT_TOKEN не настроен на сервере.")
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{TG_BOT_TOKEN}/{method}",
        data=json.dumps(params or {}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.load(resp)["result"]

def init_telegram_bot():
    global bot_username
    if not TG_BOT_TOKEN:
        logger.warning("[TELEGRAM] TG_BOT_TOKEN не задан — 2FA через Telegram отключен.")
        return
    try:
        me = tg_call("getMe")
        bot_username = me["username"]
        logger.info(f"[TELEGRAM] Бот @{bot_username} успешно подключен.")
    except Exception as e:
        logger.error(f"[TELEGRAM] Ошибка инициализации бота: {e}")

def tg_poller():
    global tg_offset
    while True:
        try:
            if not TG_BOT_TOKEN:
                time.sleep(5)
                continue
            updates = tg_call("getUpdates", {"offset": tg_offset, "timeout": 20, "allowed_updates": ["message"]})
            for upd in updates:
                tg_offset = upd["update_id"] + 1
                msg = upd.get("message") or {}
                text = (msg.get("text") or "").strip()
                chat_id = (msg.get("chat") or {}).get("id")
                if not chat_id or not text.startswith("/start"):
                    continue
                parts = text.split(maxsplit=1)
                if len(parts) < 2:
                    tg_call("sendMessage", {"chat_id": chat_id, "text": f"{APP_NAME}\nОткройте привязку в личном кабинете."})
                    continue
                with db.lock:
                    entry = link_tokens.pop(parts[1].strip(), None)
                    if entry and entry["expires"] >= time.time():
                        db.execute("UPDATE users SET tg_enc = %s WHERE username = %s", (db.enc(str(chat_id)), entry["name"]))
                    else:
                        entry = None
                if not entry:
                    tg_call("sendMessage", {"chat_id": chat_id, "text": "Ссылка устарела. Сгенерируйте новый QR-код."})
                    continue
                logger.info(f"[2FA ПРИВЯЗКА] Пользователь '{entry['name']}' привязал Telegram (chat_id={chat_id})")
                tg_call("sendMessage", {"chat_id": chat_id, "text": f"Telegram успешно привязан к учётной записи «{entry['name']}»."})
        except Exception:
            time.sleep(3)

def send_2fa_code(name: str, rec: dict, kind: str) -> str:
    cid = db.chat_id(rec.get("tg_enc", ""))
    if not cid:
        raise HTTPException(400, "К этому аккаунту не привязан Telegram.")
    code = f"{secrets.randbelow(1_000_000):06d}"
    cid_token = secrets.token_urlsafe(24)
    challenges[cid_token] = {
        "name": name, "kind": kind,
        "hash": hash_secret(code),
        "expires": time.time() + CODE_TTL, "tries": CODE_TRIES,
    }
    labels = {
        "login": "подтверждения входа",
        "tg_login": "входа по коду Telegram",
        "reset": "сброса пароля"
    }
    label = labels.get(kind, "подтверждения операции")
    try:
        tg_call("sendMessage", {"chat_id": cid, "text": f"{APP_NAME}\nКод для {label}: {code}\nДействует 5 минут."})
    except Exception:
        challenges.pop(cid_token, None)
        raise HTTPException(502, "Не удалось отправить код в Telegram. Проверьте TG_BOT_TOKEN.")
    return cid_token

def verify_2fa_code(cid_token: str, code: str, expected_kind: str) -> str:
    purge()
    ch = challenges.get(cid_token)
    if not ch or ch["kind"] != expected_kind:
        raise HTTPException(400, "Сессия подтверждения истекла. Запросите код заново.")
    if not verify_secret(code.strip(), ch["hash"]):
        ch["tries"] -= 1
        if ch["tries"] <= 0:
            challenges.pop(cid_token, None)
            raise HTTPException(400, "Превышено число попыток ввода кода.")
        raise HTTPException(400, f"Неверный код. Осталось попыток: {ch['tries']}.")
    challenges.pop(cid_token, None)
    return ch["name"]

def start_session(name: str) -> dict:
    token = secrets.token_urlsafe(32)
    sessions[token] = {"name": name, "expires": time.time() + SESSION_TTL}
    rec = db.execute("SELECT * FROM users WHERE username = %s", (name,), "one")
    logger.info(f"[АУДИТ] Создана веб-сессия для '{name}' (Роль: {rec['role']})")
    return {
        "token": token,
        "username": name,
        "role": rec["role"],
        "tg_linked": bool(rec.get("tg_enc")),
        "google_email": rec.get("google_email") or "",
        "has_password": bool(rec.get("has_password", True)) if "has_password" in rec else True,
    }

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

def require_staff(u=Depends(current_user)):
    if u["role"] not in ("user", "manager"):
        raise HTTPException(403, "Только для кассира или менеджера.")
    return u

def require_manager(u=Depends(current_user)):
    if u["role"] != "manager":
        raise HTTPException(403, "Недостаточно прав.")
    return u

def require_admin(u=Depends(current_user)):
    if u["role"] != "admin":
        raise HTTPException(403, "Только для администратора.")
    return u

def require_backup_admin(u=Depends(require_admin)):
    if not CONFIGURED_MASTER_KEY:
        raise HTTPException(503, "Задайте постоянный SERVER_MASTER_KEY в настройках Render для работы с резервными копиями.")
    return u


class LoginIn(BaseModel):
    username: str
    password: str

class TgLoginReqIn(BaseModel):
    username: str

class Verify2FAIn(BaseModel):
    challenge_id: str
    code: str

class RegisterIn(BaseModel):
    username: str
    password: str
    invite_code: str = ""

class ResetCodeIn(BaseModel):
    username: str
    recovery_code: str
    new_password: str

class ResetTgRequestIn(BaseModel):
    username: str

class ResetTgConfirmIn(BaseModel):
    challenge_id: str
    code: str
    new_password: str

class ChangePassIn(BaseModel):
    old_password: str = ""
    new_password: str

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
write_lock = asyncio.Lock()


@app.middleware("http")
async def serialize_writes(request: Request, call_next):
    path = request.url.path
    writes = request.method in ("POST", "PATCH", "DELETE", "PUT") or path.startswith("/api/oauth/google/")
    reads_backup = path.startswith("/api/admin/backup/")
    if path.startswith("/api/") and (writes or reads_backup):
        # Keep a restore or export from splitting a multi-statement app operation.
        async with write_lock:
            return await call_next(request)
    return await call_next(request)


app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def on_startup():
    seed_reference_tables()
    init_telegram_bot()
    threading.Thread(target=tg_poller, daemon=True).start()


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "db": "PostgreSQL (Supabase)",
        "tg_enabled": bool(TG_BOT_TOKEN and bot_username),
        "google_enabled": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
    }


@app.post("/api/auth/login")
def login(b: LoginIn):
    name = normalize(b.username)
    purge()
    rec = db.execute("SELECT * FROM users WHERE username = %s", (name,), "one")
    if not rec:
        verify_secret(b.password, DUMMY_HASH)
        logger.warning(f"[АУДИТ ОШИБКА] Попытка входа несуществующего логина: '{name}'")
        raise HTTPException(401, "Неверный логин или пароль.")

    lock_ts = rec["locked_until"].timestamp() if hasattr(rec.get("locked_until"), "timestamp") else float(rec.get("locked_until") or 0)
    if lock_ts > time.time():
        raise HTTPException(429, f"Аккаунт заблокирован. Подождите {int(lock_ts - time.time()) + 1} сек.")

    if not verify_secret(b.password, rec["pw_hash"]):
        failed = (rec.get("failed") or 0) + 1
        locked = time.time() + LOCK_SECONDS if failed >= MAX_ATTEMPTS else 0
        locked_dt = datetime.fromtimestamp(locked, tz=timezone.utc) if locked else None
        db.execute("UPDATE users SET failed = %s, locked_until = %s WHERE username = %s", (0 if locked else failed, locked_dt, name))
        logger.warning(f"[АУДИТ ОШИБКА] Неверный пароль для '{name}'")
        raise HTTPException(401, "Неверный логин или пароль.")

    db.execute("UPDATE users SET failed = 0 WHERE username = %s", (name,))
    if rec.get("tg_enc") and TG_BOT_TOKEN:
        cid = send_2fa_code(name, rec, "login")
        return {"status": "2fa_required", "challenge_id": cid}
    return {"status": "ok", **start_session(name)}


@app.post("/api/auth/2fa")
def login_2fa(b: Verify2FAIn):
    name = verify_2fa_code(b.challenge_id, b.code, "login")
    return {"status": "ok", **start_session(name)}


@app.post("/api/auth/login/tg/request")
def login_tg_request(b: TgLoginReqIn):
    name = normalize(b.username)
    purge()
    if not TG_BOT_TOKEN:
        raise HTTPException(400, "Telegram-бот не настроен на сервере.")
    rec = db.execute("SELECT * FROM users WHERE username = %s", (name,), "one")
    if not rec:
        raise HTTPException(404, "Учётная запись с таким логином не найдена.")
    lock_ts = rec["locked_until"].timestamp() if hasattr(rec.get("locked_until"), "timestamp") else float(rec.get("locked_until") or 0)
    if lock_ts > time.time():
        raise HTTPException(429, f"Аккаунт заблокирован. Подождите {int(lock_ts - time.time()) + 1} сек.")
    if not rec.get("tg_enc"):
        raise HTTPException(400, "К этому аккаунту не привязан Telegram. Войдите по паролю и привяжите его в профиле.")
    cid = send_2fa_code(name, rec, "tg_login")
    logger.info(f"[TELEGRAM ВХОД] Запрошен одноразовый код входа для '{name}'")
    return {"challenge_id": cid}


@app.post("/api/auth/login/tg/confirm")
def login_tg_confirm(b: Verify2FAIn):
    name = verify_2fa_code(b.challenge_id, b.code, "tg_login")
    db.execute("UPDATE users SET failed = 0 WHERE username = %s", (name,))
    logger.info(f"[TELEGRAM ВХОД] Успешный беспарольный вход для '{name}'")
    return {"status": "ok", **start_session(name)}


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
    invite_id: Optional[int] = None
    if has_admin:
        invite_id = validate_invite_code(b.invite_code)
        if invite_id is None:
            raise HTTPException(403, "Нужен действительный код приглашения от администратора.")
        role = "user"
    else:
        role = "admin"

    rec_code = new_recovery_code()
    db.execute(
        "INSERT INTO users (username, role, pw_hash, rec_hash, has_password) VALUES (%s, %s, %s, %s, TRUE)",
        (name, role, hash_secret(b.password), hash_secret(norm_code(rec_code)))
    )
    if invite_id is not None:
        mark_invite_used(invite_id, name)
    logger.info(f"[РЕГИСТРАЦИЯ] Зарегистрирован сотрудник '{name}' (Роль: {role})")
    return {"recovery_code": rec_code, "role": role}


@app.post("/api/auth/reset/recovery")
def reset_by_recovery(b: ResetCodeIn):
    name = normalize(b.username)
    if len(b.new_password) < MIN_PASSWORD:
        raise HTTPException(400, f"Новый пароль должен быть не короче {MIN_PASSWORD} символов.")
    rec = db.execute("SELECT * FROM users WHERE username = %s", (name,), "one")
    if not rec or not verify_secret(norm_code(b.recovery_code), rec["rec_hash"]):
        logger.warning(f"[СБРОС ПАРОЛЯ] Неудачная попытка сброса по коду для '{name}'")
        raise HTTPException(400, "Неверный логин или резервный код.")
    new_rec = new_recovery_code()
    db.execute(
        "UPDATE users SET pw_hash = %s, rec_hash = %s, failed = 0, locked_until = NULL, has_password = TRUE WHERE username = %s",
        (hash_secret(b.new_password), hash_secret(norm_code(new_rec)), name)
    )
    drop_sessions(name)
    logger.warning(f"[СБРОС ПАРОЛЯ] Пароль для '{name}' сброшен по резервному коду")
    return {"new_recovery_code": new_rec}


@app.post("/api/auth/reset/tg/request")
def reset_tg_req(b: ResetTgRequestIn):
    name = normalize(b.username)
    rec = db.execute("SELECT * FROM users WHERE username = %s", (name,), "one")
    if not rec:
        raise HTTPException(404, "Пользователь не найден.")
    cid = send_2fa_code(name, rec, "reset")
    return {"challenge_id": cid}


@app.post("/api/auth/reset/tg/confirm")
def reset_tg_confirm(b: ResetTgConfirmIn):
    if len(b.new_password) < MIN_PASSWORD:
        raise HTTPException(400, f"Новый пароль должен быть не короче {MIN_PASSWORD} символов.")
    name = verify_2fa_code(b.challenge_id, b.code, "reset")
    db.execute("UPDATE users SET pw_hash = %s, failed = 0, locked_until = NULL, has_password = TRUE WHERE username = %s", (hash_secret(b.new_password), name))
    drop_sessions(name)
    logger.warning(f"[СБРОС ПАРОЛЯ] Пароль для '{name}' сброшен через Telegram 2FA")
    return {"status": "ok"}


@app.post("/api/auth/logout")
def logout(u=Depends(current_user)):
    sessions.pop(u["token"], None)
    logger.info(f"[АУДИТ] Пользователь '{u['name']}' вышел из системы")
    return {"status": "ok"}


@app.get("/api/me")
def get_me(u=Depends(current_user)):
    rec = u["rec"]
    return {
        "username": u["name"],
        "role": u["role"],
        "tg_linked": bool(rec.get("tg_enc")),
        "google_email": rec.get("google_email") or "",
        "has_password": bool(rec.get("has_password", True)) if "has_password" in rec else True,
    }


@app.post("/api/me/password")
def change_password(b: ChangePassIn, u=Depends(current_user)):
    if len(b.new_password) < MIN_PASSWORD:
        raise HTTPException(400, f"Новый пароль должен быть не короче {MIN_PASSWORD} символов.")

    rec = u["rec"]
    has_pw = bool(rec.get("has_password", True)) if "has_password" in rec else True

    if has_pw:
        if not b.old_password or not verify_secret(b.old_password, rec["pw_hash"]):
            raise HTTPException(400, "Текущий пароль введён неверно.")
        db.execute("UPDATE users SET pw_hash = %s WHERE username = %s", (hash_secret(b.new_password), u["name"]))
        logger.info(f"[БЕЗОПАСНОСТЬ] Пользователь '{u['name']}' сменил пароль")
    else:
        db.execute(
            "UPDATE users SET pw_hash = %s, has_password = TRUE WHERE username = %s",
            (hash_secret(b.new_password), u["name"]),
        )
        logger.info(f"[БЕЗОПАСНОСТЬ] Пользователь '{u['name']}' задал локальный пароль для Google-аккаунта")

    return {"status": "ok"}


@app.post("/api/me/telegram/link")
def create_tg_link(u=Depends(current_user)):
    if not TG_BOT_TOKEN or not bot_username:
        raise HTTPException(400, "Telegram-бот не настроен (укажите TG_BOT_TOKEN в переменных Render).")
    purge()
    tok = secrets.token_urlsafe(18)
    link_tokens[tok] = {"name": u["name"], "expires": time.time() + LINK_TTL}
    url = f"https://t.me/{bot_username}?start={tok}"
    return {"url": url, "bot": bot_username}


@app.delete("/api/me/telegram/link")
def unlink_tg(u=Depends(current_user)):
    db.execute("UPDATE users SET tg_enc = '' WHERE username = %s", (u["name"],))
    logger.warning(f"[БЕЗОПАСНОСТЬ] Пользователь '{u['name']}' отвязал Telegram 2FA")
    return {"status": "ok"}


# --------------------------------------------------------------------------- #
#  Google OAuth 2.0 (Прямой вход без Telegram 2FA, Регистрация, Привязка)
# --------------------------------------------------------------------------- #
def google_exchange(code: str, redirect_uri: str) -> dict:
    body = urllib.parse.urlencode({
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }).encode("utf-8")
    req = urllib.request.Request(GOOGLE_TOKEN_URL, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        tokens = json.load(resp)
    id_token = tokens.get("id_token") or ""
    parts = id_token.split(".")
    if len(parts) < 2:
        raise RuntimeError("Некорректный id_token от Google.")
    pad = "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(parts[1] + pad))


@app.get("/api/oauth/google/start")
def google_start(
    request: Request,
    mode: Literal["login", "register", "link"] = "login",
    invite_code: str = "",
    desired_username: str = "",
    desired_password: str = "",
    token: str = "",
):
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(400, "Google OAuth не настроен (задайте GOOGLE_CLIENT_ID и GOOGLE_CLIENT_SECRET на Render).")
    purge()
    link_user = ""
    if mode == "link":
        s = sessions.get(token)
        if not s or s["expires"] < time.time():
            raise HTTPException(401, "Сессия истекла.")
        link_user = s["name"]

    clean_user = normalize(desired_username) if desired_username else ""
    if mode == "register":
        if clean_user:
            if not USERNAME_RE.match(clean_user):
                raise HTTPException(400, "Логин: 3–32 символа, латиница, цифры, _ . -")
            if db.execute("SELECT 1 FROM users WHERE username = %s", (clean_user,), "one"):
                raise HTTPException(400, "Этот логин уже занят.")
        if desired_password and len(desired_password) < MIN_PASSWORD:
            raise HTTPException(400, f"Пароль должен быть не короче {MIN_PASSWORD} символов.")

    state = secrets.token_urlsafe(24)
    redirect_uri = str(request.base_url).rstrip("/") + "/api/oauth/google/callback"
    oauth_states[state] = {
        "mode": mode,
        "invite_code": invite_code,
        "desired_username": clean_user,
        "desired_password": desired_password,
        "link_user": link_user,
        "redirect_uri": redirect_uri,
        "expires": time.time() + 600,
    }
    params = urllib.parse.urlencode({
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
    })
    return {"auth_url": f"https://accounts.google.com/o/oauth2/v2/auth?{params}"}


@app.get("/api/oauth/google/callback")
def google_callback(code: str = "", state: str = "", error: str = ""):
    def popup_html(payload: dict):
        return HTMLResponse(f"""<!doctype html><html><body style="background:#0f172a;color:#f8fafc;font-family:sans-serif;text-align:center;padding-top:60px">
        <h3>Авторизация завершена</h3><p>Окно закроется автоматически...</p>
        <script>
        if (window.opener) {{ window.opener.postMessage({json.dumps(payload)}, "*"); }}
        window.close();
        </script></body></html>""")

    if error or not code or not state:
        return popup_html({"type": "google_oauth", "ok": False, "error": f"Отменено или ошибка Google: {error or 'нет кода'}"})

    st = oauth_states.pop(state, None)
    if not st or st["expires"] < time.time():
        return popup_html({"type": "google_oauth", "ok": False, "error": "Сессия OAuth истекла. Попробуйте снова."})

    try:
        claims = google_exchange(code, st["redirect_uri"])
        sub = claims.get("sub", "")
        email = (claims.get("email") or "").lower()
        if not sub or not email:
            return popup_html({"type": "google_oauth", "ok": False, "error": "Google не передал email профиля."})

        mode = st["mode"]
        if mode == "link":
            owner = db.execute("SELECT username FROM users WHERE google_sub = %s", (sub,), "one")
            if owner and owner["username"] != st["link_user"]:
                return popup_html({"type": "google_oauth", "ok": False, "error": "Этот аккаунт Google уже привязан к другому сотруднику."})
            db.execute("UPDATE users SET google_sub = %s, google_email = %s WHERE username = %s", (sub, email, st["link_user"]))
            logger.info(f"[GOOGLE OAUTH] '{st['link_user']}' привязал Google ({email})")
            return popup_html({"type": "google_oauth", "ok": True, "mode": "link", "email": email})

        if mode == "login":
            rec = db.execute("SELECT * FROM users WHERE google_sub = %s", (sub,), "one")
            if not rec:
                return popup_html({"type": "google_oauth", "ok": False, "error": f"Аккаунт {email} не привязан ни к одному сотруднику."})
            lock_ts = rec["locked_until"].timestamp() if hasattr(rec.get("locked_until"), "timestamp") else float(rec.get("locked_until") or 0)
            if lock_ts > time.time():
                return popup_html({"type": "google_oauth", "ok": False, "error": "Учётная запись временно заблокирована."})
            db.execute("UPDATE users SET failed = 0 WHERE username = %s", (rec["username"],))
            logger.info(f"[GOOGLE OAUTH] Прямой вход сотрудника '{rec['username']}' ({email})")
            sess = start_session(rec["username"])
            return popup_html({"type": "google_oauth", "ok": True, "mode": "login", "session": sess})

        if mode == "register":
            if db.execute("SELECT 1 FROM users WHERE google_sub = %s", (sub,), "one"):
                return popup_html({"type": "google_oauth", "ok": False, "error": "Этот Google аккаунт уже зарегистрирован."})
            has_admin = db.execute("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1", (), "one") is not None

            custom_login = st.get("desired_username") or ""
            custom_pass = st.get("desired_password") or ""
            if custom_login:
                if not USERNAME_RE.match(custom_login):
                    return popup_html({"type": "google_oauth", "ok": False, "error": "Логин: 3–32 символа, латиница, цифры, _ . -"})
                if db.execute("SELECT 1 FROM users WHERE username = %s", (custom_login,), "one"):
                    return popup_html({"type": "google_oauth", "ok": False, "error": f"Логин «{custom_login}» уже занят."})
                uname = custom_login
            else:
                base_login = re.sub(r"[^a-z0-9_.-]", "", email.split("@")[0])[:24] or "user"
                uname = base_login
                i = 1
                while db.execute("SELECT 1 FROM users WHERE username = %s", (uname,), "one"):
                    uname = f"{base_login}{i}"
                    i += 1

            invite_id: Optional[int] = None
            if has_admin:
                invite_id = validate_invite_code(st["invite_code"])
                if invite_id is None:
                    return popup_html({"type": "google_oauth", "ok": False, "error": "Неверный или просроченный код приглашения."})
                role = "user"
            else:
                role = "admin"

            has_pw = bool(custom_pass and len(custom_pass) >= MIN_PASSWORD)
            raw_secret = custom_pass if has_pw else secrets.token_urlsafe(24)
            rec_code = new_recovery_code()
            db.execute(
                "INSERT INTO users (username, role, pw_hash, rec_hash, google_sub, google_email, has_password) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (uname, role, hash_secret(raw_secret), hash_secret(norm_code(rec_code)), sub, email, has_pw)
            )
            if invite_id is not None:
                mark_invite_used(invite_id, uname)
            logger.info(f"[GOOGLE РЕГИСТРАЦИЯ] Зарегистрирован '{uname}' через Google ({email}, роль: {role})")
            sess = start_session(uname)
            return popup_html({"type": "google_oauth", "ok": True, "mode": "register", "session": sess, "recovery_code": rec_code})

    except Exception as e:
        return popup_html({"type": "google_oauth", "ok": False, "error": f"Ошибка OAuth: {e}"})


@app.delete("/api/me/google/link")
def unlink_google(u=Depends(current_user)):
    db.execute("UPDATE users SET google_sub = NULL, google_email = '' WHERE username = %s", (u["name"],))
    logger.warning(f"[GOOGLE OAUTH] Пользователь '{u['name']}' отвязал Google")
    return {"status": "ok"}


@app.get("/api/menu")
def get_menu(u=Depends(require_staff)):
    rows = db.execute("SELECT * FROM menu WHERE is_active IS DISTINCT FROM FALSE ORDER BY id", (), "all")
    for r in rows:
        r["price"] = float(r["price"])
    return rows

@app.post("/api/menu")
def add_menu(b: MenuIn, u=Depends(require_manager)):
    cat_name = b.category.strip() or "Прочее"
    cat_id = ensure_category(cat_name)
    row = db.execute(
        "INSERT INTO menu (name, category_id, category, ingredients, price, discount, stock, is_active) VALUES (%s, %s, %s, %s, %s, 0, %s, TRUE) RETURNING *",
        (b.name.strip(), cat_id, cat_name, b.ingredients.strip(), b.price, b.stock), "one"
    )
    if row:
        row["price"] = float(row["price"])
        if b.stock > 0:
            record_stock_movement(row["id"], b.stock, "stock_in", u["name"])
    logger.info(f"[МЕНЮ] '{u['name']}' добавил блюдо '{b.name}' ({b.price} тг)")
    return row

@app.patch("/api/menu/{item_id}/discount")
def set_discount(item_id: int, b: DiscountIn, u=Depends(require_manager)):
    row = db.execute("UPDATE menu SET discount = %s WHERE id = %s RETURNING id", (b.discount, item_id), "one")
    if not row:
        raise HTTPException(404, "Позиция в меню не найдена.")
    logger.info(f"[МЕНЮ] '{u['name']}' установил скидку {b.discount}% на ID #{item_id}")
    return {"status": "ok"}

@app.patch("/api/menu/{item_id}/stock")
def set_stock(item_id: int, b: StockIn, u=Depends(require_manager)):
    cur_row = db.execute("SELECT stock FROM menu WHERE id = %s", (item_id,), "one")
    if not cur_row:
        raise HTTPException(404, "Позиция в меню не найдена.")
    delta = b.stock - int(cur_row["stock"] or 0)
    db.execute("UPDATE menu SET stock = %s WHERE id = %s", (b.stock, item_id))
    if delta != 0:
        record_stock_movement(item_id, delta, "stock_in" if delta > 0 else "adjustment", u["name"])
    logger.info(f"[СКЛАД] '{u['name']}' обновил остаток ID #{item_id} до {b.stock}")
    return {"status": "ok"}

@app.delete("/api/menu/{item_id}")
def delete_menu(item_id: int, u=Depends(require_manager)):
    db.execute("DELETE FROM stock_movements WHERE menu_item_id = %s", (item_id,))
    db.execute("DELETE FROM menu WHERE id = %s", (item_id,))
    logger.warning(f"[МЕНЮ] '{u['name']}' удалил позицию ID #{item_id}")
    return {"status": "ok"}


@app.get("/api/orders")
def get_orders(u=Depends(require_staff)):
    rows = db.execute("SELECT * FROM orders ORDER BY id DESC", (), "all")
    for r in rows:
        r["table"] = r.pop("table_name")
        r["total"] = float(r["total"])
        r["created_at"] = r["created_at"].strftime("%Y-%m-%d %H:%M") if hasattr(r["created_at"], "strftime") else str(r["created_at"])[:16]
    return rows

@app.post("/api/orders")
def create_order(b: OrderIn, u=Depends(require_staff)):
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
    table_id = ensure_table(table_name, b.type)
    summary = ", ".join(f"{l['name']} x{l['qty']}" for l in lines)
    total = round(total, 2)

    for l in lines:
        db.execute("UPDATE menu SET stock = stock - %s WHERE id = %s", (l["qty"], l["id"]))
        record_stock_movement(l["id"], -l["qty"], "sale", u["name"])

    order = db.execute(
        "INSERT INTO orders (table_id, table_name, type, items, total, payment, status, waiter) VALUES (%s, %s, %s, %s, %s, %s, 'Новый', %s) RETURNING id",
        (table_id, table_name, b.type, summary, total, b.payment, u["name"]), "one"
    )
    oid = order["id"]
    for l in lines:
        db.execute(
            "INSERT INTO order_items (order_id, menu_item_id, name, qty, price) VALUES (%s, %s, %s, %s, %s)",
            (oid, l["id"], l["name"], l["qty"], l["price"])
        )
    record_order_status_history(oid, "Новый", "Новый", u["name"])

    logger.info(f"[КАССА] Кассир '{u['name']}' оформил заказ #{oid} на {total} тг ({b.payment})")
    return {"id": oid, "total": total}

@app.patch("/api/orders/{order_id}/status")
def update_order_status(order_id: int, b: StatusIn, u=Depends(require_staff)):
    row = db.execute("SELECT status FROM orders WHERE id = %s", (order_id,), "one")
    if not row:
        raise HTTPException(404, "Заказ не найден.")
    prev_status = row["status"]
    if prev_status == b.status:
        return {"status": "ok"}

    if b.status == "Отменен" and prev_status != "Отменен":
        items = db.execute("SELECT menu_item_id, qty FROM order_items WHERE order_id = %s", (order_id,), "all")
        for it in items:
            db.execute("UPDATE menu SET stock = stock + %s WHERE id = %s", (it["qty"], it["menu_item_id"]))
            record_stock_movement(it["menu_item_id"], it["qty"], "return", u["name"])
    elif prev_status == "Отменен" and b.status != "Отменен":
        items = db.execute("SELECT menu_item_id, qty FROM order_items WHERE order_id = %s", (order_id,), "all")
        for it in items:
            db.execute("UPDATE menu SET stock = GREATEST(stock - %s, 0) WHERE id = %s", (it["qty"], it["menu_item_id"]))
            record_stock_movement(it["menu_item_id"], -it["qty"], "sale", u["name"])

    db.execute("UPDATE orders SET status = %s WHERE id = %s", (b.status, order_id))
    record_order_status_history(order_id, prev_status, b.status, u["name"])
    logger.info(f"[ЗАКАЗ] Статус заказа #{order_id} изменён с '{prev_status}' на '{b.status}' ({u['name']})")
    return {"status": "ok"}

@app.delete("/api/orders/{order_id}")
def delete_order(order_id: int, u=Depends(require_manager)):
    row = db.execute("SELECT status FROM orders WHERE id = %s", (order_id,), "one")
    if row and row["status"] in ("Новый", "Готовится"):
        items = db.execute("SELECT menu_item_id, qty FROM order_items WHERE order_id = %s", (order_id,), "all")
        for it in items:
            db.execute("UPDATE menu SET stock = stock + %s WHERE id = %s", (it["qty"], it["menu_item_id"]))
            record_stock_movement(it["menu_item_id"], it["qty"], "return", u["name"])
    db.execute("DELETE FROM order_status_history WHERE order_id = %s", (order_id,))
    db.execute("DELETE FROM order_items WHERE order_id = %s", (order_id,))
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
    db.execute("UPDATE orders SET waiter = %s WHERE waiter = %s", (u["name"], n))
    db.execute("UPDATE audit_logs SET actor = %s WHERE actor = %s", (u["name"], n))
    db.execute("UPDATE stock_movements SET actor = %s WHERE actor = %s", (u["name"], n))
    db.execute("UPDATE order_status_history SET changed_by = %s WHERE changed_by = %s", (u["name"], n))
    db.execute("UPDATE invite_codes SET created_by = %s WHERE created_by = %s", (u["name"], n))
    db.execute("UPDATE invite_codes SET used_by = %s WHERE used_by = %s", (u["name"], n))
    db.execute("DELETE FROM users WHERE username = %s", (n,))
    drop_sessions(n)
    logger.warning(f"[БЕЗОПАСНОСТЬ] Админ '{u['name']}' удалил сотрудника '{n}'")
    return {"status": "ok"}

@app.post("/api/admin/invites")
def make_invite(u=Depends(require_admin)):
    code = new_recovery_code()
    expires_at = utc_now() + timedelta(seconds=INVITE_TTL)
    db.execute(
        "INSERT INTO invite_codes (code_hash, role, created_by, expires_at) VALUES (%s, 'user', %s, %s)",
        (hash_secret(norm_code(code)), u["name"], expires_at),
    )
    logger.info(f"[БЕЗОПАСНОСТЬ] Админ '{u['name']}' сгенерировал инвайт-код")
    return {"code": code}


@app.get("/api/admin/logs")
def get_logs(start_time: Optional[str] = None, end_time: Optional[str] = None, u=Depends(require_admin)):
    rows = db.execute(
        "SELECT created_at, level, message FROM audit_logs ORDER BY id ASC",
        (),
        "all",
    )
    lines = []
    for r in rows:
        dt_str = (
            r["created_at"].strftime("%Y-%m-%d %H:%M:%S")
            if hasattr(r["created_at"], "strftime")
            else str(r["created_at"])[:19]
        )
        lines.append(f"{dt_str} | {r['level']} | {r['message']}")

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


@app.get("/api/admin/backup/logs/json")
def export_logs_json(u=Depends(require_backup_admin)):
    rows = db.execute(
        "SELECT created_at::text, level, actor, category, message FROM audit_logs ORDER BY id ASC",
        (),
        "all",
    )
    payload = {
        "exported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(rows),
        "logs": rows,
    }
    encrypted_blob = db.enc(json.dumps(payload, ensure_ascii=False))
    envelope = {
        "version": 1,
        "format": "encrypted_audit_logs_json",
        "cipher": "Fernet-AES128-CBC+HMAC-SHA256",
        "exported_at": payload["exported_at"],
        "encrypted_data": encrypted_blob,
    }
    logger.info(f"[БЭКАП ЛОГОВ] Админ '{u['name']}' выгрузил зашифрованный JSON-бэкап логов ({len(rows)} записей)")
    raw = json.dumps(envelope, ensure_ascii=False, indent=2).encode("utf-8")
    return StreamingResponse(
        io.BytesIO(raw),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=GurmanPOS_Logs_Encrypted.json"},
    )


async def read_backup_json(request: Request) -> dict:
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(400, "Файл резервной копии не удалось прочитать.")
    if not isinstance(body, dict):
        raise HTTPException(400, "Неверный формат файла резервной копии.")
    return body


@app.post("/api/admin/restore/logs/json")
def restore_logs_json(u=Depends(require_backup_admin), body=Depends(read_backup_json)):
    enc_blob = body.get("encrypted_data")
    if not isinstance(enc_blob, str) or not enc_blob:
        raise HTTPException(400, "В файле отсутствует зашифрованный блок encrypted_data.")
    try:
        payload = json.loads(db.dec(enc_blob))
        entries = payload.get("logs") if isinstance(payload, dict) else None
        if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
            raise ValueError("Некорректная структура логов.")
    except (ValueError, TypeError, InvalidToken):
        logger.error(f"[ЦЕЛОСТНОСТЬ ЛОГОВ] Админ '{u['name']}' загрузил файл с неверным ключом или форматом")
        raise HTTPException(400, "Не удалось расшифровать бэкап логов. Проверьте файл и SERVER_MASTER_KEY.")

    try:
        with db.transaction():
            db.execute("LOCK TABLE users IN SHARE MODE")
            db.execute("LOCK TABLE audit_logs IN SHARE ROW EXCLUSIVE MODE")
            db.execute("DELETE FROM audit_logs")
            for item in entries:
                db.execute(
                    """
                    INSERT INTO audit_logs (created_at, level, actor, category, message)
                    VALUES (COALESCE(%s, CURRENT_TIMESTAMP), %s,
                            (SELECT username FROM users WHERE username = %s), %s, %s)
                    """,
                    (
                        item.get("created_at"),
                        (item.get("level") or "INFO")[:16],
                        item.get("actor"),
                        (item.get("category") or "АУДИТ")[:64],
                        item.get("message") or "",
                    ),
                )
    except (psycopg2.Error, TypeError) as exc:
        reason = getattr(exc, "pgcode", None) or type(exc).__name__
        logger.error(f"[ВОССТАНОВЛЕНИЕ ЛОГОВ] Ошибка загрузки копии ({u['name']}), код {reason}")
        raise HTTPException(409, "Восстановление логов отменено. Записи журнала сохранены.")
    logger.warning(f"[ВОССТАНОВЛЕНИЕ ЛОГОВ] Админ '{u['name']}' восстановил {len(entries)} записей логов из зашифрованного JSON")
    return {"status": "ok", "restored": len(entries)}


@app.get("/api/admin/backup/bak")
@app.get("/api/admin/backup/json")
def export_bak(u=Depends(require_backup_admin)):
    with db.transaction(readonly=True):
        users = db.execute(
            """
            SELECT username, role, pw_hash, rec_hash, tg_enc, google_sub, google_email,
                   failed, locked_until::text, has_password, created_at::text
            FROM users ORDER BY username
            """,
            (),
            "all",
        )
        categories = db.execute("SELECT id, name, sort_order, color FROM categories ORDER BY id", (), "all")
        dining_tables = db.execute("SELECT id, label, seats, zone, status FROM dining_tables ORDER BY id", (), "all")
        menu = db.execute("SELECT id, name, category_id, category, ingredients, price::float, discount, stock, is_active FROM menu ORDER BY id", (), "all")
        orders = db.execute("SELECT id, table_id, table_name, type, items, total::float, payment, status, waiter, created_at::text FROM orders ORDER BY id", (), "all")
        order_items = db.execute("SELECT id, order_id, menu_item_id, name, qty, price::float FROM order_items ORDER BY id", (), "all")
        order_status_history = db.execute("SELECT id, order_id, old_status, new_status, changed_by, changed_at::text FROM order_status_history ORDER BY id", (), "all")
        stock_movements = db.execute("SELECT id, menu_item_id, delta, reason, actor, created_at::text FROM stock_movements ORDER BY id", (), "all")
        invite_codes = db.execute("SELECT id, code_hash, role, created_by, expires_at::text, used_by, used_at::text FROM invite_codes ORDER BY id", (), "all")

    data_block = _canonicalize_numbers({
        "users": users,
        "categories": categories,
        "dining_tables": dining_tables,
        "menu": menu,
        "orders": orders,
        "order_items": order_items,
        "order_status_history": order_status_history,
        "stock_movements": stock_movements,
        "invite_codes": invite_codes,
    })
    snapshot = {
        "version": 5,
        "format": "gurmanpos_db_bak",
        "engine": "PostgreSQL (Supabase)",
        "exported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "integrity_hmac_sha256": compute_integrity_hmac(data_block),
        "data": data_block
    }
    logger.info(f"[БЭКАП] Админ '{u['name']}' выгрузил подписанный дамп БД (.bak)")
    raw = json.dumps(snapshot, ensure_ascii=False, indent=2).encode("utf-8")
    return StreamingResponse(io.BytesIO(raw), media_type="application/octet-stream",
                             headers={"Content-Disposition": "attachment; filename=GurmanPOS_Backup.bak"})


def restart_id_sequence(table: str):
    row = db.execute(
        sql.SQL("""
            SELECT ns.nspname, seq.relname,
                   COALESCE((SELECT MAX(id) + 1 FROM {}), seq_config.seqstart) AS next_id
            FROM pg_class seq
            JOIN pg_namespace ns ON ns.oid = seq.relnamespace
            JOIN pg_sequence seq_config ON seq_config.seqrelid = seq.oid
            WHERE seq.oid = pg_get_serial_sequence(%s, 'id')::regclass
        """).format(sql.Identifier(table)),
        (table,),
        "one",
    )
    if row:
        db.execute(
            sql.SQL("ALTER SEQUENCE {} RESTART WITH %s").format(sql.Identifier(row["nspname"], row["relname"])),
            (row["next_id"],),
        )


def replace_database(data_block: dict):
    db.execute(
        "LOCK TABLE users, audit_logs, categories, dining_tables, menu, orders, order_items, "
        "order_status_history, stock_movements, invite_codes IN SHARE ROW EXCLUSIVE MODE"
    )
    # Keep the audit journal and reattach actors whose accounts are in the backup.
    db.execute("CREATE TEMP TABLE restore_audit_actors ON COMMIT DROP AS SELECT id, actor FROM audit_logs WHERE actor IS NOT NULL")
    db.execute("UPDATE audit_logs SET actor = NULL WHERE actor IS NOT NULL")

    for table in (
        "order_status_history", "order_items", "stock_movements", "orders", "menu",
        "dining_tables", "categories", "invite_codes", "users",
    ):
        db.execute(sql.SQL("DELETE FROM {}").format(sql.Identifier(table)))

    for r in data_block["users"]:
        db.execute(
            "INSERT INTO users (username, role, pw_hash, rec_hash, tg_enc, google_sub, google_email, failed, locked_until, has_password, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, COALESCE(%s, CURRENT_TIMESTAMP))",
            (r["username"], r["role"], r["pw_hash"], r["rec_hash"], r.get("tg_enc", ""), r.get("google_sub"), r.get("google_email"), r.get("failed", 0), r.get("locked_until"), r.get("has_password", True), r.get("created_at"))
        )
    for c in data_block.get("categories", []):
        db.execute(
            "INSERT INTO categories (id, name, sort_order, color) OVERRIDING SYSTEM VALUE VALUES (%s, %s, %s, %s)",
            (c["id"], c["name"], c.get("sort_order", 0), c.get("color", "#B9A4F5"))
        )
    for t in data_block.get("dining_tables", []):
        db.execute(
            "INSERT INTO dining_tables (id, label, seats, zone, status) OVERRIDING SYSTEM VALUE VALUES (%s, %s, %s, %s, %s)",
            (t["id"], t["label"], t.get("seats", 4), t.get("zone", "Основной зал"), t.get("status", "free"))
        )
    restart_id_sequence("categories")
    restart_id_sequence("dining_tables")
    for m in data_block.get("menu", []):
        cat_id = m.get("category_id") or ensure_category(m.get("category", "Прочее"))
        db.execute(
            "INSERT INTO menu (id, name, category_id, category, ingredients, price, discount, stock, is_active) OVERRIDING SYSTEM VALUE VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (m["id"], m["name"], cat_id, m["category"], m["ingredients"], m["price"], m["discount"], m["stock"], m.get("is_active", True))
        )
    for o in data_block.get("orders", []):
        tbl_id = o.get("table_id") or ensure_table(o["table_name"], o.get("type", "В заведении"))
        db.execute(
            "INSERT INTO orders (id, table_id, table_name, type, items, total, payment, status, waiter, created_at) OVERRIDING SYSTEM VALUE VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (o["id"], tbl_id, o["table_name"], o["type"], o["items"], o["total"], o["payment"], o["status"], o["waiter"], o["created_at"])
        )
    for oi in data_block.get("order_items", []):
        db.execute(
            "INSERT INTO order_items (id, order_id, menu_item_id, name, qty, price) OVERRIDING SYSTEM VALUE VALUES (%s, %s, %s, %s, %s, %s)",
            (oi["id"], oi["order_id"], oi["menu_item_id"], oi["name"], oi["qty"], oi["price"])
        )
    for h in data_block.get("order_status_history", []):
        db.execute(
            "INSERT INTO order_status_history (id, order_id, old_status, new_status, changed_by, changed_at) OVERRIDING SYSTEM VALUE VALUES (%s, %s, %s, %s, %s, %s)",
            (h["id"], h["order_id"], h["old_status"], h["new_status"], h.get("changed_by"), h.get("changed_at"))
        )
    for sm in data_block.get("stock_movements", []):
        db.execute(
            "INSERT INTO stock_movements (id, menu_item_id, delta, reason, actor, created_at) OVERRIDING SYSTEM VALUE VALUES (%s, %s, %s, %s, %s, %s)",
            (sm["id"], sm["menu_item_id"], sm["delta"], sm["reason"], sm.get("actor"), sm.get("created_at"))
        )
    for ic in data_block.get("invite_codes", []):
        db.execute(
            "INSERT INTO invite_codes (id, code_hash, role, created_by, expires_at, used_by, used_at) OVERRIDING SYSTEM VALUE VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (ic["id"], ic["code_hash"], ic["role"], ic.get("created_by"), ic.get("expires_at"), ic.get("used_by"), ic.get("used_at"))
        )

    for table in ("menu", "orders", "order_items", "order_status_history", "stock_movements", "invite_codes"):
        restart_id_sequence(table)

    db.execute(
        """
        UPDATE audit_logs AS logs SET actor = saved.actor
        FROM restore_audit_actors AS saved JOIN users ON users.username = saved.actor
        WHERE logs.id = saved.id
        """
    )


@app.post("/api/admin/restore/bak")
@app.post("/api/admin/restore/json")
def restore_bak(u=Depends(require_backup_admin), snapshot=Depends(read_backup_json)):
    data_block = snapshot.get("data")
    sig = snapshot.get("integrity_hmac_sha256")
    if not isinstance(data_block, dict) or not isinstance(sig, str) or not re.fullmatch(r"[0-9a-f]{64}", sig):
        raise HTTPException(400, "Неверный формат файла бэкапа или отсутствует подпись целостности.")

    if not hmac.compare_digest(sig, compute_integrity_hmac(data_block)):
        logger.warning(f"[ЦЕЛОСТНОСТЬ] Подпись файла бэкапа не совпала ({u['name']})")
        raise HTTPException(400, "Подпись бэкапа не совпала. Проверьте файл и SERVER_MASTER_KEY, которым он был подписан.")

    version = snapshot.get("version")
    required_tables = {"users", "menu", "orders"}
    if version in (4, 5):
        required_tables.add("order_items")
    if version == 5:
        required_tables.update(("categories", "dining_tables", "order_status_history", "stock_movements", "invite_codes"))
    if version not in (3, 4, 5) or not required_tables.issubset(data_block) or any(
        not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
        for rows in data_block.values()
    ):
        raise HTTPException(400, "Неподдерживаемая версия или неполная структура бэкапа.")
    if not any(row.get("role") == "admin" for row in data_block["users"]):
        raise HTTPException(400, "В бэкапе должна быть хотя бы одна учётная запись администратора.")

    try:
        with db.lock:
            with db.transaction():
                replace_database(data_block)
                if version < 5:
                    seed_reference_tables()
            for store in (sessions, challenges, link_tokens, oauth_states):
                store.clear()
    except (psycopg2.Error, KeyError, TypeError) as exc:
        reason = getattr(exc, "pgcode", None) or type(exc).__name__
        logger.error(f"[ВОССТАНОВЛЕНИЕ] Ошибка загрузки бэкапа ({u['name']}), код {reason}")
        raise HTTPException(409, "Восстановление отменено. Данные базы сохранены.")

    logger.warning(f"[ВОССТАНОВЛЕНИЕ] БД успешно восстановлена из .bak ({u['name']})")
    return {"status": "ok"}


@app.get("/api/admin/backup/excel")
def export_excel(u=Depends(require_admin)):
    output = io.BytesIO()
    with db.transaction(readonly=True):
        df_orders = pd.read_sql_query("SELECT id, table_name AS Стол, type AS Тип, items AS Состав, total AS Сумма, payment AS Оплата, status AS Статус, waiter AS Кассир FROM orders", db.conn)
        df_menu = pd.read_sql_query("SELECT id, name AS Блюдо, category AS Категория, price AS Цена, discount AS Скидка, stock AS Остаток FROM menu", db.conn)
        df_users = pd.read_sql_query("SELECT username AS Логин, role AS Роль, google_email AS Google FROM users", db.conn)
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df_orders.to_excel(writer, sheet_name="Заказы", index=False)
        df_menu.to_excel(writer, sheet_name="Меню", index=False)
        df_users.to_excel(writer, sheet_name="Сотрудники", index=False)
    output.seek(0)
    return StreamingResponse(output, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                             headers={"Content-Disposition": "attachment; filename=GurmanPOS_Report.xlsx"})


if os.path.exists(STATIC_DIR):
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
