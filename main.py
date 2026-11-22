import os
import re
import time
import ssl
import hmac
import hashlib
import logging
import threading
import sqlite3
from datetime import datetime
from zoneinfo import ZoneInfo

MOSCOW_TZ = ZoneInfo("Europe/Moscow")
from pathlib import Path
from copy import deepcopy

import requests
from flask import Flask, request, jsonify
from requests.adapters import HTTPAdapter
import json
import gspread
from google.oauth2.service_account import Credentials


# =========================================================
# НАСТРОЙКИ И ПОДКЛЮЧЕНИЕ MAX
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

TOKEN = os.getenv("MAX_TOKEN")
WEBHOOK_SECRET = os.getenv("MAX_WEBHOOK_SECRET")
ADMIN_USER_ID = os.getenv("ADMIN_USER_ID")

if not TOKEN or not WEBHOOK_SECRET:
    raise RuntimeError("Не заданы MAX_TOKEN или MAX_WEBHOOK_SECRET")

if not re.fullmatch(r"[A-Za-z0-9_-]{5,256}", WEBHOOK_SECRET):
    raise RuntimeError("Недопустимый формат MAX_WEBHOOK_SECRET")

API_URL = "https://platform-api2.max.ru"
HEADERS = {"Authorization": TOKEN}
WEBHOOK_URL = (
    "https://bot-1794067708-7548-maksim-z.bothost.tech/webhook"
)

CA_FILE = Path(__file__).resolve().parent / "russian_trusted_sub_ca_2024.pem"

EXPECTED_SHA256 = (
    "2155785036c900dbb5f1bb2a1569c80c"
    "55595bd6bf94867a29bbddbc7d88a3f2"
)

if not CA_FILE.exists():
    raise FileNotFoundError(f"Не найден сертификат: {CA_FILE}")

pem_data = CA_FILE.read_text(encoding="ascii")
der_data = ssl.PEM_cert_to_DER_cert(pem_data)

if hashlib.sha256(der_data).hexdigest() != EXPECTED_SHA256:
    raise RuntimeError("Отпечаток сертификата не совпадает")

ssl_context = ssl.create_default_context()
ssl_context.load_verify_locations(cafile=str(CA_FILE))
ssl_context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN


class ContextAdapter(HTTPAdapter):
    def __init__(self, context):
        self.context = context
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self.context
        return super().init_poolmanager(*args, **kwargs)


session = requests.Session()
session.mount(
    "https://platform-api2.max.ru/",
    ContextAdapter(ssl_context)
)

app = Flask(__name__)


# =========================================================
# ВРЕМЕННЫЕ ДАННЫЕ ПОЛЬЗОВАТЕЛЕЙ
# =========================================================

order_states = {}
lead_states = {}
admin_search_states = set()

# Постоянное хранилище Bothost
DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_FILE = DATA_DIR / "orders_history.sqlite3"
GOOGLE_SHEET_ID = "1H9wwHnRb4-EWDrJPtd66U48miw9HfIuDZzP4krzyo3o"
logging.info("База заказов и заявок: %s", DB_FILE)


def connect_google_sheets():
    try:
        credentials_json = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")

        if not credentials_json:
            logging.error("Не задан GOOGLE_SERVICE_ACCOUNT_JSON")
            return None

        credentials_data = json.loads(credentials_json)
        credentials = Credentials.from_service_account_info(
            credentials_data,
            scopes=["https://www.googleapis.com/auth/spreadsheets"]
        )

        client = gspread.authorize(credentials)
        spreadsheet = client.open_by_key(GOOGLE_SHEET_ID)
        logging.info("Google Таблица успешно подключена")
        return spreadsheet

    except Exception:
        logging.exception("Ошибка подключения Google Таблиц")
        return None


def init_history_db():
    with sqlite3.connect(DB_FILE) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS order_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                total REAL NOT NULL,
                result TEXT NOT NULL
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_order_history_user "
            "ON order_history(user_id, id DESC)"
        )
        connection.execute("""
            CREATE TABLE IF NOT EXISTS customer_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                customer_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                result TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Новая'
            )
        """)
        # Безопасная миграция существующей базы: данные заявок не удаляются.
        columns = {
            row[1] for row in connection.execute(
                "PRAGMA table_info(customer_requests)"
            ).fetchall()
        }
        if "archived" not in columns:
            connection.execute(
                "ALTER TABLE customer_requests "
                "ADD COLUMN archived INTEGER NOT NULL DEFAULT 0"
            )
        if "archive_reason" not in columns:
            connection.execute(
                "ALTER TABLE customer_requests ADD COLUMN archive_reason TEXT"
            )
        for column_name in ("address", "locality", "contact_time", "comment"):
            if column_name not in columns:
                connection.execute(
                    f"ALTER TABLE customer_requests ADD COLUMN {column_name} TEXT"
                )
        if "group_notified" not in columns:
            # Для старых заявок ставим 1, чтобы при первом запуске не рассылать историю.
            connection.execute(
                "ALTER TABLE customer_requests "
                "ADD COLUMN group_notified INTEGER NOT NULL DEFAULT 1"
            )
        if "photos" not in columns:
            # Храним переиспользуемые media-токены MAX, чтобы фото можно было
            # повторно отправить администратору и в рабочую группу.
            connection.execute(
                "ALTER TABLE customer_requests "
                "ADD COLUMN photos TEXT NOT NULL DEFAULT '[]'"
            )

        connection.execute("""
            CREATE TABLE IF NOT EXISTS bot_settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL
            )
        """)

        # Уже завершённые заявки переводим в архив при первом запуске новой версии.
        connection.execute(
            "UPDATE customer_requests "
            "SET archived = 1, archive_reason = COALESCE(archive_reason, 'Завершена') "
            "WHERE status = 'Завершена' AND archived = 0"
        )

        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_customer_requests_archive_status "
            "ON customer_requests(archived, status, id DESC)"
        )


def save_order_history(user_id, total, result):
    with sqlite3.connect(DB_FILE) as connection:
        connection.execute(
            "INSERT INTO order_history (user_id, created_at, total, result) "
            "VALUES (?, ?, ?, ?)",
            (str(user_id), datetime.now(MOSCOW_TZ).strftime("%d.%m.%Y %H:%M"), float(total), result)
        )


def show_order_history(user_id):
    with sqlite3.connect(DB_FILE) as connection:
        rows = connection.execute(
            "SELECT id, created_at, total FROM order_history "
            "WHERE user_id = ? ORDER BY id DESC LIMIT 10",
            (str(user_id),)
        ).fetchall()

    if not rows:
        send_message(
            user_id,
            "📋 История заказов пока пуста.\n\n"
            "Здесь будут отображаться ваши сохранённые расчёты.",
            [[{"type": "callback", "text": "🏠 Главное меню", "payload": "menu"}]]
        )
        return

    items = []
    lines = ["📋 ВАША ИСТОРИЯ ЗАКАЗОВ", "", "Последние 10 расчётов:"]
    for order_id, created_at, total in rows:
        lines.append(f"№{order_id} — {created_at} — {total:.2f} ₽")
        items.append((f"Открыть заказ №{order_id}", f"history_view:{order_id}"))
    items.append(("🏠 Главное меню", "menu"))
    send_message(user_id, "\n".join(lines), keyboard(items, 1))


def show_history_order(user_id, order_id):
    with sqlite3.connect(DB_FILE) as connection:
        row = connection.execute(
            "SELECT created_at, result FROM order_history "
            "WHERE id = ? AND user_id = ?",
            (int(order_id), str(user_id))
        ).fetchone()

    if not row:
        send_message(user_id, "Этот заказ не найден в вашей истории.")
        return

    created_at, result = row
    send_message(
        user_id,
        f"📋 ЗАКАЗ №{order_id}\nДата: {created_at}\n\n{result}",
        [[{"type": "callback", "text": "⬅️ К истории заказов", "payload": "history"}],
         [{"type": "callback", "text": "🏠 Главное меню", "payload": "menu"}]]
    )


init_history_db()


def is_admin(user_id):
    return bool(ADMIN_USER_ID) and str(user_id) == str(ADMIN_USER_ID)


def _google_sheet_row_index(worksheet, order_id):
    """Возвращает номер строки заявки по ID в первом столбце."""
    for row_number, value in enumerate(worksheet.col_values(1), start=1):
        if row_number > 1 and str(value).strip() == str(order_id):
            return row_number
    return None


def _upsert_google_sheet_row(worksheet, values):
    """Обновляет существующую строку или добавляет её без дублирования ID."""
    row_number = _google_sheet_row_index(worksheet, values[0])
    if row_number:
        worksheet.update(
            values=[values],
            range_name=f"A{row_number}:L{row_number}",
            value_input_option="USER_ENTERED"
        )
    else:
        worksheet.append_row(values, value_input_option="USER_ENTERED")


def combine_object_address(address, legacy_locality=""):
    """Объединяет адрес и старое отдельное поле района в одну строку."""
    address = str(address or "").strip()
    legacy_locality = str(legacy_locality or "").strip()

    if not legacy_locality:
        return address
    if not address:
        return legacy_locality
    if legacy_locality.casefold() in address.casefold():
        return address
    return f"{address}, {legacy_locality}"


GOOGLE_SHEET_LAYOUT_LOCK = threading.Lock()


def ensure_google_sheet_layout(worksheet):
    """Убирает устаревший столбец района, сохраняя время связи и комментарий."""
    # Защита от одновременной миграции листа двумя потоками при запуске бота.
    with GOOGLE_SHEET_LAYOUT_LOCK:
        headers = worksheet.row_values(1)
        if len(headers) >= 10 and str(headers[9]).strip().casefold() in {
            "район / населённый пункт",
            "район или населённый пункт"
        }:
            # Значения старого поля района остаются в SQLite и объединяются с адресом.
            worksheet.delete_columns(10)
            headers = worksheet.row_values(1)

        expected_headers = [
            "Удобное время для связи",
            "Комментарий клиента",
            "Фотографии объекта"
        ]
        if headers[9:12] != expected_headers:
            worksheet.update(
                values=[expected_headers],
                range_name="J1:L1",
                value_input_option="RAW"
            )


def _delete_google_sheet_rows(worksheet, order_id):
    """Удаляет все строки с данным ID из листа (заголовок не затрагивает)."""
    matching_rows = [
        row_number
        for row_number, value in enumerate(worksheet.col_values(1), start=1)
        if row_number > 1 and str(value).strip() == str(order_id)
    ]
    for row_number in reversed(matching_rows):
        worksheet.delete_rows(row_number)


def parse_photo_tokens(photos_json):
    """Возвращает безопасный список MAX media-токенов из поля SQLite."""
    try:
        values = json.loads(photos_json or "[]")
    except (TypeError, json.JSONDecodeError):
        logging.warning("Некорректный JSON со списком фотографий заявки")
        return []

    if not isinstance(values, list):
        return []

    tokens = []
    for value in values:
        if isinstance(value, str) and value.strip() and value not in tokens:
            tokens.append(value.strip())
    return tokens[:10]


def extract_total_from_result(result):
    """Извлекает общую сумму из сохранённого текста расчёта.

    Поддерживает текущий формат «ОБЩАЯ СТОИМОСТЬ» и прежний формат «Итого».
    Для заявок без расчёта возвращает пустую ячейку.
    """
    if not result:
        return ""

    patterns = (
        # Текущий калькулятор: 💰 ОБЩАЯ СТОИМОСТЬ: 1234.56 ₽
        r"(?im)^.*?ОБЩАЯ\s+СТОИМОСТЬ\s*[:：—-]\s*"
        r"([0-9][0-9\s\u00a0]*(?:[.,][0-9]{1,2})?)\s*(?:₽|руб(?:\.|лей|ля)?)?.*$",
        # Возможный прежний вариант подписи.
        r"(?im)^.*?ИТОГОВАЯ\s+СТОИМОСТЬ\s*[:：—-]\s*"
        r"([0-9][0-9\s\u00a0]*(?:[.,][0-9]{1,2})?)\s*(?:₽|руб(?:\.|лей|ля)?)?.*$",
        # Старый формат: «Итого: 1050.00 ₽»; исключаем «Итого бурение».
        r"(?im)^\s*(?:💰\s*)?ИТОГО(?:\s+ЗАКАЗА)?\s*[:：—-]?\s*"
        r"([0-9][0-9\s\u00a0]*(?:[.,][0-9]{1,2})?)\s*(?:₽|руб(?:\.|лей|ля)?)?\s*$",
    )

    for pattern in patterns:
        match = re.search(pattern, str(result))
        if match:
            amount = match.group(1).replace("\u00a0", "").replace(" ", "").replace(",", ".")
            try:
                return round(float(amount), 2)
            except ValueError:
                logging.warning("Не удалось разобрать сумму в расчёте: %r", match.group(1))
                return ""

    return ""


def sync_request_to_google(order_id):
    """Синхронизирует одну заявку из SQLite в нужный лист Google Таблицы."""
    with sqlite3.connect(DB_FILE) as connection:
        row = connection.execute(
            "SELECT id, created_at, customer_name, phone, result, status, archived, "
            "address, locality, contact_time, comment, photos "
            "FROM customer_requests WHERE id = ?",
            (int(order_id),)
        ).fetchone()

    if not row:
        return False

    request_id, created_at, customer_name, phone, result, status, archived, \
        address, locality, contact_time, comment, photos_json = row
    photo_tokens = parse_photo_tokens(photos_json)
    spreadsheet = connect_google_sheets()
    if not spreadsheet:
        return False

    active_sheet = spreadsheet.worksheet("Активные")
    archive_sheet = spreadsheet.worksheet("Архив")

    # Удаляем старую отдельную колонку района: район теперь вводится вместе с адресом.
    for worksheet in (active_sheet, archive_sheet):
        ensure_google_sheet_layout(worksheet)

    full_address = combine_object_address(address, locality)
    section = "Архив" if archived else "Активная"
    values = [
        request_id,
        created_at,
        customer_name,
        phone,
        full_address,
        result,
        extract_total_from_result(result),
        status,
        section,
        contact_time or "",
        comment or "",
        f"{len(photo_tokens)} фото" if photo_tokens else ""
    ]

    if archived:
        # Сначала гарантируем запись в архиве, затем убираем её из активного листа.
        _upsert_google_sheet_row(archive_sheet, values)
        _delete_google_sheet_rows(active_sheet, request_id)
    else:
        _upsert_google_sheet_row(active_sheet, values)
        _delete_google_sheet_rows(archive_sheet, request_id)

    return True


def sync_all_requests_to_google():
    """Первичная и повторная сверка всех заявок SQLite с Google Таблицей."""
    try:
        with sqlite3.connect(DB_FILE) as connection:
            rows = connection.execute(
                "SELECT id FROM customer_requests ORDER BY id"
            ).fetchall()

        if not rows:
            logging.info("Нет заявок для синхронизации с Google Таблицей")
            return

        synced = 0
        failed = 0
        for (order_id,) in rows:
            try:
                if sync_request_to_google(order_id):
                    synced += 1
                else:
                    failed += 1
            except Exception:
                failed += 1
                logging.exception(
                    "Ошибка синхронизации заявки №%s", order_id
                )

        logging.info(
            "Сверка Google Таблицы завершена: успешно %s, ошибок %s",
            synced, failed
        )
    except Exception:
        logging.exception("Не удалось выполнить сверку заявок с Google Таблицей")


def save_customer_request(
    user_id, customer_name, phone, result,
    address="", contact_time="", comment="", photos=None
):
    created_at = datetime.now(MOSCOW_TZ).strftime("%d.%m.%Y %H:%M")

    with sqlite3.connect(DB_FILE) as connection:
        cursor = connection.execute(
            "INSERT INTO customer_requests "
            "(user_id, created_at, customer_name, phone, result, status, "
            "address, contact_time, comment, group_notified, photos) "
            "VALUES (?, ?, ?, ?, ?, 'Новая', ?, ?, ?, 0, ?)",
            (
                str(user_id), created_at, customer_name, phone, result,
                address, contact_time, comment,
                json.dumps(parse_photo_tokens(json.dumps(photos or [])), ensure_ascii=False)
            )
        )
        order_id = cursor.lastrowid

    try:
        synced = sync_request_to_google(order_id)
        if synced:
            logging.info("Заявка №%s синхронизирована с Google Таблицей", order_id)
        else:
            logging.warning("Заявка №%s сохранена в SQLite, но Google Таблица пока не обновлена", order_id)
    except Exception:
        logging.exception(
            "Не удалось синхронизировать заявку №%s с Google Таблицей",
            order_id
        )

    return order_id


def show_admin_panel(user_id):
    if not is_admin(user_id):
        send_message(user_id, "⛔ Доступ запрещён.")
        return

    with sqlite3.connect(DB_FILE) as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM customer_requests"
        ).fetchone()[0]
        active_count = connection.execute(
            "SELECT COUNT(*) FROM customer_requests WHERE archived = 0"
        ).fetchone()[0]
        new_count = connection.execute(
            "SELECT COUNT(*) FROM customer_requests "
            "WHERE archived = 0 AND status = 'Новая'"
        ).fetchone()[0]
        work_count = connection.execute(
            "SELECT COUNT(*) FROM customer_requests "
            "WHERE archived = 0 AND status = 'В работе'"
        ).fetchone()[0]
        archive_count = connection.execute(
            "SELECT COUNT(*) FROM customer_requests WHERE archived = 1"
        ).fetchone()[0]

    buttons = [
        [{"type": "callback", "text": "📥 Все активные заявки", "payload": "admin_orders"}],
        [{"type": "callback", "text": "🆕 Новые заявки", "payload": "admin_orders_new"}],
        [{"type": "callback", "text": "🔧 Заявки в работе", "payload": "admin_orders_work"}],
        [{"type": "callback", "text": "🗃 Архив заявок", "payload": "admin_archive"}],
        [{"type": "callback", "text": "🔎 Поиск по имени или телефону", "payload": "admin_search"}],
        [{"type": "callback", "text": "🏠 Главное меню", "payload": "menu"}],
    ]
    send_message(
        user_id,
        f"🛠 АДМИН-ПАНЕЛЬ\n\nВсего заявок: {total}\n"
        f"Активных: {active_count}\nНовых: {new_count}\n"
        f"В работе: {work_count}\nВ архиве: {archive_count}",
        buttons
    )


def show_admin_orders(user_id, only_new=False, status=None, search_term=None):
    if not is_admin(user_id):
        send_message(user_id, "⛔ Доступ запрещён.")
        return

    if only_new:
        status = "Новая"

    conditions = ["archived = 0"]
    params = []
    if status:
        conditions.append("status = ?")
        params.append(status)

    query = (
        "SELECT id, created_at, customer_name, phone, status "
        "FROM customer_requests WHERE " + " AND ".join(conditions) +
        " ORDER BY id DESC"
    )
    with sqlite3.connect(DB_FILE) as connection:
        rows = connection.execute(query, params).fetchall()

    if search_term:
        term = search_term.strip().casefold()
        rows = [
            row for row in rows
            if term in str(row[2] or "").casefold()
            or term in str(row[3] or "").casefold()
            or term in str(row[0])
        ]
        title = f"🔎 РЕЗУЛЬТАТЫ ПОИСКА: {search_term}"
    elif status == "Новая":
        title = "🆕 НОВЫЕ ЗАЯВКИ"
    elif status == "В работе":
        title = "🔧 ЗАЯВКИ В РАБОТЕ"
    else:
        title = "📋 АКТИВНЫЕ ЗАЯВКИ"

    rows = rows[:20]
    if not rows:
        buttons = [
            [{"type": "callback", "text": "🔎 Новый поиск", "payload": "admin_search"}],
            [{"type": "callback", "text": "🗃 Архив", "payload": "admin_archive"}],
            [{"type": "callback", "text": "⬅️ В админ-панель", "payload": "admin_panel"}],
        ]
        send_message(user_id, f"{title}\n\nНичего не найдено.", buttons)
        return

    lines = [title, "", "Показаны последние 20 подходящих заявок:"]
    buttons = []
    for order_id, created_at, name, phone, order_status in rows:
        lines.append(
            f"№{order_id} — {name} — {phone} — {order_status} — {created_at}"
        )
        buttons.append([{
            "type": "callback",
            "text": f"Открыть заявку №{order_id}",
            "payload": f"admin_order:{order_id}"
        }])

    buttons.extend([
        [{"type": "callback", "text": "🔎 Поиск", "payload": "admin_search"}],
        [{"type": "callback", "text": "🗃 Архив", "payload": "admin_archive"}],
        [{"type": "callback", "text": "⬅️ В админ-панель", "payload": "admin_panel"}],
    ])
    send_message(user_id, "\n".join(lines), buttons)


def show_admin_archive(user_id, only_completed=False):
    if not is_admin(user_id):
        send_message(user_id, "⛔ Доступ запрещён.")
        return

    query = (
        "SELECT id, created_at, customer_name, phone, status, archive_reason "
        "FROM customer_requests WHERE archived = 1"
    )
    params = []
    if only_completed:
        query += " AND status = ?"
        params.append("Завершена")
    query += " ORDER BY id DESC LIMIT 20"

    with sqlite3.connect(DB_FILE) as connection:
        rows = connection.execute(query, params).fetchall()

    title = "✅ ЗАВЕРШЁННЫЕ ЗАЯВКИ" if only_completed else "🗃 АРХИВ ЗАЯВОК"
    if not rows:
        send_message(
            user_id,
            f"{title}\n\nВ архиве пока нет заявок.",
            [[{"type": "callback", "text": "⬅️ В админ-панель", "payload": "admin_panel"}]]
        )
        return

    lines = [title, "", "Последние 20 заявок:"]
    buttons = []
    for order_id, created_at, name, phone, order_status, reason in rows:
        suffix = f" ({reason})" if reason else ""
        lines.append(
            f"№{order_id} — {name} — {phone} — {order_status} — {created_at}{suffix}"
        )
        buttons.append([{
            "type": "callback",
            "text": f"Открыть заявку №{order_id}",
            "payload": f"admin_archive_order:{order_id}"
        }])
    buttons.append([{"type": "callback", "text": "⬅️ В админ-панель", "payload": "admin_panel"}])
    send_message(user_id, "\n".join(lines), buttons)


def start_admin_search(user_id):
    if not is_admin(user_id):
        send_message(user_id, "⛔ Доступ запрещён.")
        return
    admin_search_states.add(str(user_id))
    send_message(
        user_id,
        "🔎 Поиск заявок\n\nВведите имя клиента, часть имени, номер телефона "
        "или номер заявки. Для отмены нажмите кнопку ниже.",
        [[{"type": "callback", "text": "Отмена поиска", "payload": "admin_search_cancel"}],
         [{"type": "callback", "text": "⬅️ В админ-панель", "payload": "admin_panel"}]]
    )


def process_admin_search(user_id, search_term):
    uid = str(user_id)
    admin_search_states.discard(uid)
    if not is_admin(user_id):
        send_message(user_id, "⛔ Доступ запрещён.")
        return
    term = search_term.strip()
    if not term:
        send_message(user_id, "Введите имя, телефон или номер заявки для поиска.")
        start_admin_search(user_id)
        return
    show_admin_orders(user_id, search_term=term)


def show_admin_order(user_id, order_id, from_archive=False):
    if not is_admin(user_id):
        send_message(user_id, "⛔ Доступ запрещён.")
        return
    with sqlite3.connect(DB_FILE) as connection:
        row = connection.execute(
            "SELECT user_id, created_at, customer_name, phone, result, status, "
            "archived, archive_reason, address, locality, contact_time, comment, photos "
            "FROM customer_requests WHERE id = ?",
            (int(order_id),)
        ).fetchone()
    if not row:
        send_message(user_id, "Заявка не найдена.")
        return

    (
        client_id, created_at, name, phone, result, status, archived, reason,
        address, locality, contact_time, comment, photos_json
    ) = row
    photo_tokens = parse_photo_tokens(photos_json)
    section = "Архив" if archived else "Активные заявки"
    buttons = [
        [{"type": "callback", "text": "🆕 Новая", "payload": f"admin_status:{order_id}:Новая"}],
        [{"type": "callback", "text": "🔧 В работе", "payload": f"admin_status:{order_id}:В работе"}],
        [{"type": "callback", "text": "✅ Завершена", "payload": f"admin_status:{order_id}:Завершена"}],
    ]
    if not archived:
        buttons.append([{
            "type": "callback",
            "text": "🗃 Переместить в архив",
            "payload": f"admin_delete_confirm:{order_id}"
        }])
    back_payload = "admin_archive" if from_archive or archived else "admin_orders"
    back_text = "⬅️ К архиву" if from_archive or archived else "⬅️ К активным заявкам"
    buttons.append([{"type": "callback", "text": back_text, "payload": back_payload}])

    reason_line = f"\nПричина архивации: {reason}" if reason else ""
    optional_lines = []
    full_address = combine_object_address(address, locality)
    if full_address:
        optional_lines.append(f"Адрес объекта: {full_address}")
    if contact_time:
        optional_lines.append(f"Удобное время для связи: {contact_time}")
    if comment:
        optional_lines.append(f"Комментарий клиента: {comment}")
    if photo_tokens:
        optional_lines.append(f"Фотографии объекта: {len(photo_tokens)} шт. (отправлены в уведомлении)")
    optional_details = "\n".join(optional_lines)
    optional_block = f"\n\nДополнительная информация:\n{optional_details}" if optional_details else ""

    send_message(
        user_id,
        f"📋 ЗАЯВКА №{order_id}\nДата: {created_at}\nСтатус: {status}"
        f"\nРаздел: {section}{reason_line}\n\n"
        f"Имя: {name}\nТелефон: {phone}\nID клиента MAX: {client_id}"
        f"{optional_block}\n\n{result}",
        buttons
    )


def set_admin_order_status(user_id, order_id, status):
    if not is_admin(user_id):
        send_message(user_id, "⛔ Доступ запрещён.")
        return
    if status not in ("Новая", "В работе", "Завершена"):
        send_message(user_id, "Недопустимый статус.")
        return

    is_archived = 1 if status == "Завершена" else 0
    archive_reason = "Завершена" if is_archived else None
    with sqlite3.connect(DB_FILE) as connection:
        cursor = connection.execute(
            "UPDATE customer_requests "
            "SET status = ?, archived = ?, archive_reason = ? WHERE id = ?",
            (status, is_archived, archive_reason, int(order_id))
        )
        found = cursor.rowcount > 0

    if not found:
        send_message(user_id, "Заявка не найдена.")
        return

    try:
        sync_request_to_google(order_id)
    except Exception:
        logging.exception("Не удалось синхронизировать заявку №%s с Google Таблицей", order_id)

    if is_archived:
        send_message(user_id, f"✅ Заявка №{order_id} завершена и перемещена в архив.")
        show_admin_order(user_id, order_id, from_archive=True)
    else:
        send_message(user_id, f"✅ Статус заявки №{order_id} изменён: {status}. Заявка возвращена в активные.")
        show_admin_order(user_id, order_id)


# =========================================================
# ТАРИФЫ
# Цена указана в рублях за 1 сантиметр бурения
# =========================================================

DIAMETERS = {
    40: {"Кирпич": 17, "Бетон": 24, "Армированный бетон": 30},
    50: {"Кирпич": 13, "Бетон": 15, "Армированный бетон": 18},
    60: {"Кирпич": 14, "Бетон": 16, "Армированный бетон": 19},
    80: {"Кирпич": 15, "Бетон": 17, "Армированный бетон": 21},
    100: {"Кирпич": 16, "Бетон": 18, "Армированный бетон": 22},
    110: {"Кирпич": 18, "Бетон": 19, "Армированный бетон": 23},
    130: {"Кирпич": 20, "Бетон": 21, "Армированный бетон": 25},
    140: {"Кирпич": 21, "Бетон": 22, "Армированный бетон": 26},
    160: {"Кирпич": 22, "Бетон": 24, "Армированный бетон": 28},
    170: {"Кирпич": 23, "Бетон": 27, "Армированный бетон": 30},
    180: {"Кирпич": 24, "Бетон": 28, "Армированный бетон": 32},
    200: {"Кирпич": 26, "Бетон": 30, "Армированный бетон": 34},
    220: {"Кирпич": 30, "Бетон": 32, "Армированный бетон": 37},
    270: {"Кирпич": 34, "Бетон": 37, "Армированный бетон": 42},
    325: {"Кирпич": 40, "Бетон": 50, "Армированный бетон": 60},
    350: {"Кирпич": 60, "Бетон": 65, "Армированный бетон": 70},
    400: {"Кирпич": 60, "Бетон": 85, "Армированный бетон": 90},
    500: {"Кирпич": 70, "Бетон": 85, "Армированный бетон": 105},
}

# Ночной коэффициент обрабатывается отдельно на весь заказ.
COEFFICIENTS = {
    "angle": ("Бурение под углом", 1.3),
    "cold": ("Температура от 0 до -5 °C", 1.5),
    "hard": ("Труднодоступное место", 1.2),
}

HEIGHTS = {
    "h1": ("Высота выше 1,8 м", 1.2),
    "h2": ("Высота выше 3 м", 1.5),
    "h3": ("Высота выше 5 м", 2.0),
}

EXTRAS = {
    "water": ("Сбор воды", 600),
    "travel": ("Выезд за пределы города до 10 км", 500),
    "waste": ("Вывоз мусора", None),
}


# =========================================================
# ОБЩИЕ ФУНКЦИИ
# =========================================================

def send_message(user_id, text, buttons=None, photo_tokens=None):
    body = {"text": text}
    attachments = [
        {"type": "image", "payload": {"token": token}}
        for token in parse_photo_tokens(json.dumps(photo_tokens or []))
    ]

    if buttons:
        attachments.append({
            "type": "inline_keyboard",
            "payload": {"buttons": buttons}
        })

    if attachments:
        body["attachments"] = attachments

    response = session.post(
        f"{API_URL}/messages",
        headers=HEADERS,
        params={"user_id": user_id},
        json=body,
        timeout=20
    )

    logging.info(
        "Ответ MAX: %s %s",
        response.status_code,
        response.text
    )
    response.raise_for_status()


def notify_admin(text, photo_tokens=None):
    if not ADMIN_USER_ID:
        raise RuntimeError("Не задан ADMIN_USER_ID")

    buttons = [[
        {
            "type": "callback",
            "text": "⚙️ Открыть админ-панель",
            "payload": "admin_panel"
        }
    ]]

    send_message(ADMIN_USER_ID, text, buttons, photo_tokens=photo_tokens)


WORK_GROUP_BIND_COMMAND = "!привязать_рабочую_группу"
GROUP_NOTIFICATIONS_LOCK = threading.Lock()


def get_work_group_chat_id():
    with sqlite3.connect(DB_FILE) as connection:
        row = connection.execute(
            "SELECT setting_value FROM bot_settings WHERE setting_key = ?",
            ("work_group_chat_id",)
        ).fetchone()
    return row[0] if row else None


def set_work_group_chat_id(chat_id):
    with sqlite3.connect(DB_FILE) as connection:
        connection.execute(
            "INSERT INTO bot_settings (setting_key, setting_value) VALUES (?, ?) "
            "ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value",
            ("work_group_chat_id", str(int(chat_id)))
        )


def clear_work_group_chat_id(chat_id):
    with sqlite3.connect(DB_FILE) as connection:
        connection.execute(
            "DELETE FROM bot_settings WHERE setting_key = ? AND setting_value = ?",
            ("work_group_chat_id", str(chat_id))
        )


def send_group_message(chat_id, text, photo_tokens=None):
    # В MAX для группового чата используется query-параметр chat_id, не user_id.
    attachments = [
        {"type": "image", "payload": {"token": token}}
        for token in parse_photo_tokens(json.dumps(photo_tokens or []))
    ]
    body = {"text": text[:3900]}
    if attachments:
        body["attachments"] = attachments

    response = session.post(
        f"{API_URL}/messages",
        headers=HEADERS,
        params={"chat_id": int(chat_id)},
        json=body,
        timeout=20
    )
    logging.info(
        "Ответ MAX для рабочей группы %s: %s",
        chat_id,
        response.status_code
    )
    response.raise_for_status()


def format_group_request(row):
    order_id, created_at, name, phone, result, address, locality, contact_time, comment, photos_json = row
    photo_tokens = parse_photo_tokens(photos_json)
    details = [
        f"📥 НОВАЯ ЗАЯВКА №{order_id}",
        f"📅 Дата: {created_at}",
        f"👤 Клиент: {name}",
        f"📞 Телефон: {phone}"
    ]
    full_address = combine_object_address(address, locality)
    if full_address:
        details.append(f"📍 Адрес объекта: {full_address}")
    if contact_time:
        details.append(f"🕒 Удобное время для связи: {contact_time}")
    if comment:
        details.append(f"💬 Комментарий клиента: {comment}")
    if photo_tokens:
        details.append(f"📷 Фотографии объекта: {len(photo_tokens)} шт.")
    details.extend([
        "",
        str(result or "Заявка без предварительного расчёта."),
        "",
        "💬 Обсудите заказ в этом рабочем чате. Номер заявки сохранён в боте."
    ])
    message = "\n".join(details)
    if len(message) > 3900:
        message = message[:3800] + "\n\n… Полный расчёт сохранён в карточке заявки бота."
    return message


def sync_pending_group_notifications():
    """Отправляет в рабочую группу новые заявки, ещё не отмеченные как доставленные."""
    chat_id = get_work_group_chat_id()
    if not chat_id:
        return

    # Не допускаем параллельной отправки одной очереди из разных потоков.
    with GROUP_NOTIFICATIONS_LOCK:
        with sqlite3.connect(DB_FILE) as connection:
            rows = connection.execute(
                "SELECT id, created_at, customer_name, phone, result, address, "
                "locality, contact_time, comment, photos "
                "FROM customer_requests WHERE group_notified = 0 ORDER BY id"
            ).fetchall()

        for row in rows:
            order_id = row[0]
            try:
                send_group_message(
                    chat_id,
                    format_group_request(row),
                    photo_tokens=parse_photo_tokens(row[9])
                )
            except Exception:
                logging.exception(
                    "Не удалось отправить заявку №%s в рабочую группу; она останется в очереди",
                    order_id
                )
                break

            with sqlite3.connect(DB_FILE) as connection:
                connection.execute(
                    "UPDATE customer_requests SET group_notified = 1 "
                    "WHERE id = ? AND group_notified = 0",
                    (order_id,)
                )
            # Документация MAX ограничивает отправку двумя сообщениями в секунду в один чат.
            if len(rows) > 1:
                time.sleep(0.55)


def keyboard(items, columns=2):
    rows = []

    for i in range(0, len(items), columns):
        rows.append([
            {
                "type": "callback",
                "text": title,
                "payload": payload
            }
            for title, payload in items[i:i + columns]
        ])

    return rows


def clear_user_data(uid):
    order_states.pop(uid, None)
    lead_states.pop(uid, None)



def main_menu(user_id):
    uid = str(user_id)
    clear_user_data(uid)

    buttons = [
        [{
            "type": "callback",
            "text": "💵 Рассчитать стоимость",
            "payload": "price"
        }],
        [{
            "type": "callback",
            "text": "📩 Заказать без расчёта",
            "payload": "request_start"
        }],
        [{
            "type": "callback",
            "text": "⚙️ Наши услуги",
            "payload": "services"
        }],
        [{
            "type": "callback",
            "text": "📍 География работ",
            "payload": "location"
        }],
        [{
            "type": "callback",
            "text": "📋 История заказов",
            "payload": "history"
        }],
        [{
            "type": "callback",
            "text": "📞 Связаться с нами",
            "payload": "contact"
        }],
    ]

    if is_admin(user_id):
        buttons.append([{
            "type": "callback",
            "text": "🛠 Админ-панель",
            "payload": "admin_panel"
        }])

    send_message(
        user_id,
        "💎  АЛМАЗНОЕ БУРЕНИЕ\n"
        "━━━━━━━━━━━━━━━━━━\n\n"
        "Добро пожаловать!\n\n"
        "Профессиональное алмазное бурение "
        "отверстий в кирпиче, бетоне и "
        "армированном бетоне.\n\n"
        "📍 Санкт-Петербург и Ленинградская область\n\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "ТОЧНОСТЬ • НАДЁЖНОСТЬ • КАЧЕСТВО\n\n"
        "Выберите интересующий вас раздел:",
        buttons
    )



# =========================================================
# НОВЫЙ КАЛЬКУЛЯТОР ЗАКАЗА
# =========================================================

def start_order(user_id):
    uid = str(user_id)

    lead_states.pop(uid, None)
    order_states[uid] = {
        "positions": [],
        "current": None,
        "extras": set()
    }

    ask_position_diameter(user_id)



def ask_position_diameter(user_id):
    uid = str(user_id)
    state = order_states[uid]
    position_number = len(state["positions"]) + 1

    items = [
        (f"💎 {diameter} мм", f"order_diam:{diameter}")
        for diameter in DIAMETERS
    ]
    items.append(("❌ Отмена заказа", "cancel"))

    send_message(
        user_id,
        "💎  АЛМАЗНОЕ БУРЕНИЕ\n"
        "━━━━━━━━━━━━━━━━━━\n\n"
        "НОВЫЙ ЗАКАЗ\n\n"
        f"📌 ПОЗИЦИЯ №{position_number}\n\n"
        "📏 ВЫБОР ДИАМЕТРА\n\n"
        "Выберите необходимый диаметр отверстия:\n\n",
        keyboard(items)
    )




def ask_position_material(user_id):
    items = [
        ("🧱 Кирпич", "order_material:Кирпич"),
        ("🏗 Бетон", "order_material:Бетон"),
        ("⚙️ Армированный бетон", "order_material:Армированный бетон"),
        ("⬅️ Назад к диаметру", "order_back:diameter"),
        ("❌ Отмена заказа", "cancel"),
    ]

    send_message(
        user_id,
        "💎  АЛМАЗНОЕ БУРЕНИЕ\n"
        "━━━━━━━━━━━━━━━━━━\n\n"
        "НОВЫЙ ЗАКАЗ\n\n"
        "🧱 ВЫБОР МАТЕРИАЛА\n\n"
        "Укажите материал стены, в которой "
        "необходимо выполнить отверстие:\n\n",
        keyboard(items, 1)
    )




def ask_position_depth(user_id):
    uid = str(user_id)
    order_states[uid]["step"] = "depth"

    send_message(
        user_id,
        "💎  АЛМАЗНОЕ БУРЕНИЕ\n"
        "━━━━━━━━━━━━━━━━━━\n\n"
        "НОВЫЙ ЗАКАЗ\n\n"
        "📏 ГЛУБИНА ОТВЕРСТИЯ\n\n"
        "Укажите глубину одного отверстия "
        "в сантиметрах.\n\n"
        "Например: 30\n\n"
        "Можно использовать запятую или точку.\n\n",
        [[
            {
                "type": "callback",
                "text": "⬅️ Назад к материалу",
                "payload": "order_back:material"
            },
            {
                "type": "callback",
                "text": "❌ Отмена заказа",
                "payload": "cancel"
            }
        ]]
    )



def ask_position_quantity(user_id):
    uid = str(user_id)
    order_states[uid]["step"] = "quantity"

    send_message(
        user_id,
        "💎  АЛМАЗНОЕ БУРЕНИЕ\n"
        "━━━━━━━━━━━━━━━━━━\n\n"
        "НОВЫЙ ЗАКАЗ\n\n"
        "🔢 КОЛИЧЕСТВО ОТВЕРСТИЙ\n\n"
        "Сколько одинаковых отверстий "
        "с выбранными параметрами необходимо пробурить?\n\n"
        "Укажите количество целым числом.\n\n"
        "Например: 5\n\n",
        [[
            {
                "type": "callback",
                "text": "⬅️ Назад к глубине",
                "payload": "order_back:depth"
            },
            {
                "type": "callback",
                "text": "❌ Отмена заказа",
                "payload": "cancel"
            }
        ]]
    )



def ask_position_conditions(user_id):
    uid = str(user_id)
    state = order_states[uid]
    data = state["current"]

    lines = [
        "💎  АЛМАЗНОЕ БУРЕНИЕ",
        "━━━━━━━━━━━━━━━━━━",
        "",
        "НОВЫЙ ЗАКАЗ",
        "",
        f"⚙️ УСЛОВИЯ БУРЕНИЯ — ПОЗИЦИЯ №{len(state['positions']) + 1}",
        "",
        "Выберите дополнительные условия.",
        "Нажимайте кнопки, чтобы включить или выключить их.",
        ""
    ]

    items = []

    for key, (name, factor) in COEFFICIENTS.items():
        mark = "✓ " if key in data["conditions"] else ""
        items.append((mark + name, f"order_cond:{key}"))

    for key, (name, factor) in HEIGHTS.items():
        mark = "✓ " if data["height"] == key else ""
        items.append((mark + name, f"order_height:{key}"))

    night_mark = "✓ " if data["night"] else ""
    items.append((night_mark + "🌙 Ночное время (20:00–8:00)", "order_night"))

    if data["conditions"] or data["height"] or data["night"]:
        lines.append("📌 ВЫБРАННЫЕ УСЛОВИЯ:")
        for key in data["conditions"]:
            name, factor = COEFFICIENTS[key]
            lines.append(f"• {name}: ×{factor}")

        if data["height"]:
            name, factor = HEIGHTS[data["height"]]
            lines.append(f"• {name}: ×{factor}")

        if data["night"]:
            lines.append("• Ночное время: ×1,5 на весь заказ")

    lines.extend([
        "",
    ])

    items.append(("⬅️ Назад к количеству", "order_back:quantity"))
    items.append(("💾 Сохранить позицию", "order_save_position"))
    items.append(("❌ Отмена заказа", "cancel"))

    send_message(
        user_id,
        "\n".join(lines),
        keyboard(items, 1)
    )



def ask_after_position(user_id):

    uid = str(user_id)
    count = len(order_states[uid]["positions"])

    items = [
        ("➕ Добавить ещё одну позицию", "order_add_position"),
        ("✅ Завершить заказ и рассчитать", "order_finish"),
        ("❌ Отмена заказа", "cancel"),
    ]

    send_message(
        user_id,
        "💎  АЛМАЗНОЕ БУРЕНИЕ\n"
        "━━━━━━━━━━━━━━━━━━\n\n"
        "✅ ПОЗИЦИЯ СОХРАНЕНА\n\n"
        f"📋 В ЗАКАЗЕ ПОЗИЦИЙ: {count}\n\n"
        "Вы можете добавить отверстия "
        "с другими параметрами или перейти "
        "к итоговому расчёту заказа.\n\n",
        keyboard(items, 1)
    )



def ask_order_extras(user_id):

    uid = str(user_id)
    selected = order_states[uid]["extras"]

    items = []

    for key, (name, price) in EXTRAS.items():
        mark = "✓ " if key in selected else ""
        price_text = (
            "по договорённости"
            if price is None
            else f"{price} ₽"
        )
        items.append((
            f"{mark}{name} ({price_text})",
            f"order_extra:{key}"
        ))

    items.extend([
        ("💰 Рассчитать стоимость заказа", "order_calculate"),
        ("➕ Вернуться к позициям", "order_add_position"),
        ("❌ Отмена заказа", "cancel"),
    ])

    send_message(
        user_id,
        "💎  АЛМАЗНОЕ БУРЕНИЕ\n"
        "━━━━━━━━━━━━━━━━━━\n\n"
        "🛠 ДОПОЛНИТЕЛЬНЫЕ УСЛУГИ\n\n"
        "Выберите дополнительные услуги "
        "для всего заказа.\n\n"
        "Отмечайте необходимые пункты кнопками.\n"
        "Каждая выбранная услуга учитывается "
        "один раз на весь заказ.\n\n",
        keyboard(items, 1)
    )



def calculate_order(user_id):

    uid = str(user_id)
    state = order_states.get(uid)

    if not state or not state["positions"]:
        send_message(
            user_id,
            "💎  АЛМАЗНОЕ БУРЕНИЕ\n"
            "━━━━━━━━━━━━━━━━━━\n\n"
            "⚠️ В заказе пока нет ни одной позиции.\n\n"
            "Добавьте хотя бы одну позицию для расчёта."
        )
        return

    lines = [
        "💎  АЛМАЗНОЕ БУРЕНИЕ\n",
        "━━━━━━━━━━━━━━━━━━",
        "",
        "📋 ПРЕДВАРИТЕЛЬНАЯ СМЕТА ЗАКАЗА",
        ""
    ]

    drilling_subtotal = 0.0
    has_night = any(
        position.get("night", False)
        for position in state["positions"]
    )

    for index, position in enumerate(state["positions"], start=1):
        diameter = position["diameter"]
        material = position["material"]
        depth = position["depth"]
        quantity = position["quantity"]

        rate = DIAMETERS[diameter][material]
        base_one = rate * depth

        coefficient = 1.0
        details = []

        if depth > 50:
            coefficient *= 1.5
            details.append("глубина свыше 50 см ×1,5")

        for key in position["conditions"]:
            name, factor = COEFFICIENTS[key]
            coefficient *= factor
            details.append(f"{name} ×{factor}")

        if position["height"]:
            name, factor = HEIGHTS[position["height"]]
            coefficient *= factor
            details.append(f"{name} ×{factor}")

        one_hole_price = base_one * coefficient
        position_total = one_hole_price * quantity
        drilling_subtotal += position_total

        lines.extend([
            "━━━━━━━━━━━━━━━━━━",
            f"📌 ПОЗИЦИЯ №{index}",
            f"📏 Диаметр: {diameter} мм",
            f"🧱 Материал: {material}",
            f"Глубина одного отверстия: {depth:g} см",
            f"🔢 Количество отверстий: {quantity}",
            "",
            f"Цена за 1 см: {rate} ₽",
            f"Стоимость одного отверстия: {one_hole_price:.2f} ₽",
            f"💰 СТОИМОСТЬ ПОЗИЦИИ: {position_total:.2f} ₽",
        ])

        if details:
            lines.append("Условия: " + "; ".join(details))

        if position.get("night"):
            lines.append(
                "🌙 Ночное время выбрано: коэффициент будет применён ко всему заказу."
            )

        lines.append("")

    if has_night:
        before_night = drilling_subtotal
        drilling_subtotal *= 1.5
        lines.extend([
            "━━━━━━━━━━━━━━━━━━",
            "🌙 НОЧНОЙ КОЭФФИЦИЕНТ ×1,5",
            "Применён один раз ко всему бурению заказа.",
            f"Бурение до коэффициента: {before_night:.2f} ₽",
            f"Бурение с коэффициентом: {drilling_subtotal:.2f} ₽",
            ""
        ])

    extra_total = 0
    extra_lines = []

    for key in state["extras"]:
        name, price = EXTRAS[key]

        if price is None:
            extra_lines.append(
                f"{name}: стоимость согласуется с менеджером"
            )
        else:
            extra_total += price
            extra_lines.append(f"{name}: {price} ₽")

    total = drilling_subtotal + extra_total

    lines.append(f"💎 ИТОГО БУРЕНИЕ: {drilling_subtotal:.2f} ₽")

    if extra_lines:
        lines.append("")
        lines.append("🛠 ДОПОЛНИТЕЛЬНЫЕ УСЛУГИ:")
        lines.extend(extra_lines)
        lines.append(
            f"Стоимость услуг с фиксированной ценой: {extra_total:.2f} ₽"
        )

    lines.extend([
        "",
        "━━━━━━━━━━━━━━━━━━",
        f"💰 ОБЩАЯ СТОИМОСТЬ: {total:.2f} ₽",
        "━━━━━━━━━━━━━━━━━━",
        "",
        "Это предварительный расчёт.",
        "Окончательная стоимость уточняется "
        "после согласования деталей заказа."
    ])

    if "waste" in state["extras"]:
        lines.append(
            "Вывоз мусора оплачивается отдельно по договорённости."
        )

    lines.extend([
        "",
    ])

    result = "\n".join(lines)

    # Сохраняем завершённый расчёт в постоянную историю клиента.
    save_order_history(user_id, total, result)

    # Сохраняем смету для последующего оформления заявки.
    lead_states[uid] = {
        "step": "ready",
        "result": result
    }

    order_states.pop(uid, None)

    send_message(
        user_id,
        result + "\n\n📩 Хотите оформить заявку?",
        [
            [{
                "type": "callback",
                "text": "📩 Оставить заявку",
                "payload": "lead_start"
            }],
            [{
                "type": "callback",
                "text": "🔄 Новый расчёт",
                "payload": "price"
            }],
            [{
                "type": "callback",
                "text": "🏠 Главное меню",
                "payload": "menu"
            }],
        ]
    )


# =========================================================
# ЗАЯВКА: С РАСЧЁТОМ И БЕЗ РАСЧЁТА
# =========================================================


def start_lead(user_id, result):
    uid = str(user_id)
    order_states.pop(uid, None)

    lead_states[uid] = {
        "step": "name",
        "result": result,
        "address": "",
        "contact_time": "",
        "comment": "",
        "photos": []
    }

    send_message(
        user_id,
        "💎  АЛМАЗНОЕ БУРЕНИЕ\n"
        "━━━━━━━━━━━━━━━━━━\n\n"
        "📩 ОФОРМЛЕНИЕ ЗАЯВКИ\n\n"
        "Благодарим за обращение!\n\n"
        "Чтобы наш менеджер мог связаться с вами, "
        "пожалуйста, укажите ваше имя."
    )


def ask_lead_phone(user_id):
    uid = str(user_id)
    lead_states[uid]["step"] = "phone"

    send_message(
        user_id,
        "💎  АЛМАЗНОЕ БУРЕНИЕ\n"
        "━━━━━━━━━━━━━━━━━━\n\n"
        "📞 КОНТАКТНЫЙ НОМЕР\n\n"
        "Укажите номер телефона, по которому "
        "наш менеджер сможет связаться с вами.\n\n"
        "Например: +79991234567\n\n"
        "Этот номер обязателен для обратной связи."
    )


def ask_optional_lead_field(user_id, step):
    """Показывает необязательное поле заявки с кнопкой пропуска."""
    uid = str(user_id)
    state = lead_states.get(uid)
    if not state:
        return

    prompts = {
        "address": (
            "📍 Адрес объекта\n\n"
            "Укажите улицу, дом, район или населённый пункт. При необходимости добавьте корпус, помещение или другие ориентиры.\n"
            "Это поле необязательное — можно пропустить."
        ),
        "contact_time": (
            "🕒 Удобное время для связи\n\n"
            "Например: после 18:00 или в будние дни с 10:00 до 17:00.\n"
            "Это поле необязательное — можно пропустить."
        ),
        "comment": (
            "💬 Комментарий к заявке\n\n"
            "Можете добавить пожелания или важные подробности.\n"
            "Это поле необязательное — можно пропустить."
        )
    }

    if step not in prompts:
        logging.error("Неизвестный шаг необязательной заявки: %s", step)
        return

    state["step"] = step
    send_message(
        user_id,
        prompts[step],
        [[{
            "type": "callback",
            "text": "Пропустить",
            "payload": f"lead_skip:{step}"
        }]]
    )


MAX_REQUEST_PHOTOS = 10


def ask_lead_photos(user_id):
    """Предлагает клиенту приложить фотографии объекта; шаг необязательный."""
    uid = str(user_id)
    state = lead_states.get(uid)
    if not state:
        return

    state["step"] = "photos"
    count = len(state.get("photos", []))
    send_message(
        user_id,
        "📷 Фотографии объекта\n\n"
        "Можете отправить до 10 фотографий места будущего бурения. "
        "Отправляйте их по одной или несколькими за раз.\n\n"
        f"Уже получено: {count} из {MAX_REQUEST_PHOTOS}.\n"
        "Когда закончите, нажмите «Готово». Этот шаг можно пропустить.",
        [[{
            "type": "callback",
            "text": "✅ Готово",
            "payload": "lead_photos_done"
        }], [{
            "type": "callback",
            "text": "Пропустить фотографии",
            "payload": "lead_skip_photos"
        }]]
    )


def process_lead_photo_message(user_id, attachments):
    """Сохраняет токены фотографий MAX в состоянии оформления заявки."""
    uid = str(user_id)
    state = lead_states.get(uid)
    if not state or state.get("step") != "photos":
        return

    current = state.setdefault("photos", [])
    received = []
    invalid_images = 0

    for attachment in attachments or []:
        if not isinstance(attachment, dict) or attachment.get("type") != "image":
            continue
        payload = attachment.get("payload") or {}
        token = payload.get("token")
        if not token:
            invalid_images += 1
            continue
        token = str(token).strip()
        if token and token not in current and token not in received:
            received.append(token)

    available = max(0, MAX_REQUEST_PHOTOS - len(current))
    accepted = received[:available]
    current.extend(accepted)

    if invalid_images:
        logging.warning(
            "Получены изображения без повторно используемого token от user_id=%s",
            user_id
        )

    if not accepted:
        send_message(
            user_id,
            "Не удалось принять фотографии. Отправьте изображения ещё раз "
            "или нажмите «Готово» для продолжения."
        )
        return

    count = len(current)
    send_message(
        user_id,
        f"✅ Получено фотографий: {count} из {MAX_REQUEST_PHOTOS}.\n"
        "Можете отправить ещё или нажать «Готово».",
        [[{
            "type": "callback",
            "text": "✅ Готово",
            "payload": "lead_photos_done"
        }], [{
            "type": "callback",
            "text": "Пропустить фотографии",
            "payload": "lead_skip_photos"
        }]]
    )

    if len(received) > available:
        send_message(
            user_id,
            f"Можно прикрепить не более {MAX_REQUEST_PHOTOS} фотографий к одной заявке."
        )


def advance_optional_lead_field(user_id, current_step):
    next_steps = {
        "address": "contact_time",
        "contact_time": "comment"
    }
    next_step = next_steps.get(current_step)
    if next_step:
        ask_optional_lead_field(user_id, next_step)
    else:
        ask_lead_photos(user_id)


def skip_optional_lead_field(user_id, field):
    uid = str(user_id)
    state = lead_states.get(uid)
    allowed_fields = ("address", "contact_time", "comment")

    if not state or field not in allowed_fields or state.get("step") != field:
        send_message(user_id, "Этот шаг уже завершён. Продолжите оформление заявки.")
        return

    state[field] = ""
    advance_optional_lead_field(user_id, field)


def finalize_lead(user_id):
    uid = str(user_id)
    state = lead_states.get(uid)
    if not state:
        return

    if not state.get("request_id"):
        state["request_id"] = save_customer_request(
            user_id,
            state["name"],
            state["phone"],
            state["result"],
            address=state.get("address", ""),
            contact_time=state.get("contact_time", ""),
            comment=state.get("comment", ""),
            photos=state.get("photos", [])
        )

    request_id = state["request_id"]
    details = []
    full_address = combine_object_address(state.get("address", ""))
    if full_address:
        details.append(f"📍 Адрес объекта: {full_address}")
    if state.get("contact_time"):
        details.append(f"🕒 Удобное время для связи: {state['contact_time']}")
    if state.get("comment"):
        details.append(f"💬 Комментарий клиента: {state['comment']}")
    photo_tokens = parse_photo_tokens(json.dumps(state.get("photos", [])))
    if photo_tokens:
        details.append(f"📷 Фотографии объекта: {len(photo_tokens)} шт. (прикреплены ниже)")
    details_text = "\n".join(details)
    details_block = f"\n\n{details_text}" if details_text else ""

    admin_message = (
        f"💎 НОВАЯ ЗАЯВКА №{request_id}\n"
        "━━━━━━━━━━━━━━━━━━\n\n"
        f"👤 Имя: {state['name']}\n"
        f"📞 Телефон: {state['phone']}\n"
        f"🆔 ID клиента MAX: {user_id}"
        f"{details_block}\n\n"
        f"{state['result']}\n\n"
        "Откройте админ-панель бота, чтобы изменить статус заявки."
    )

    admin_notification_failed = False
    try:
        notify_admin(admin_message, photo_tokens=photo_tokens)
    except Exception:
        admin_notification_failed = True
        logging.exception("Не удалось отправить заявку администратору")
        state["step"] = "notify_retry"
        send_message(
            user_id,
            "⚠️ Заявка сохранена, но уведомление менеджеру не отправлено. "
            "Нажмите кнопку ниже, чтобы повторить отправку.\n\n"
            "Повторная отправка не создаст дубликат заявки.",
            [[{
                "type": "callback",
                "text": "🔄 Повторить отправку",
                "payload": "lead_retry_notification"
            }]]
        )

    # Групповое уведомление отправляется независимо от личного уведомления.
    # Если группа ещё не привязана или MAX временно недоступен, заявка остаётся в очереди.
    try:
        sync_pending_group_notifications()
    except Exception:
        logging.exception("Ошибка отправки новых заявок в рабочую группу")

    if admin_notification_failed:
        return

    lead_states.pop(uid, None)
    send_message(
        user_id,
        "💎  АЛМАЗНОЕ БУРЕНИЕ\n"
        "━━━━━━━━━━━━━━━━━━\n\n"
        "✅ ВАША ЗАЯВКА ОТПРАВЛЕНА!\n\n"
        "Благодарим за обращение.\n"
        "Наш менеджер свяжется с вами "
        "в ближайшее время.",
        [[{
            "type": "callback",
            "text": "🏠 Главное меню",
            "payload": "menu"
        }]]
    )


def process_lead_message(user_id, text):
    uid = str(user_id)
    state = lead_states.get(uid)
    if not state:
        return

    step = state.get("step")

    if step == "name":
        name = text.strip()
        if len(name) < 2:
            send_message(
                user_id,
                "⚠️ Пожалуйста, введите корректное имя.\n"
                "Имя должно содержать не менее двух символов."
            )
            return
        state["name"] = name
        ask_lead_phone(user_id)
        return

    if step == "phone":
        phone = text.strip()
        digits = "".join(filter(str.isdigit, phone))
        if len(digits) < 10 or len(digits) > 15:
            send_message(
                user_id,
                "⚠️ Некорректный номер телефона. Проверьте номер и отправьте его ещё раз.\n"
                "Например: +79991234567"
            )
            return
        state["phone"] = phone
        ask_optional_lead_field(user_id, "address")
        return

    field_limits = {
        "address": 300,
        "contact_time": 150,
        "comment": 1000
    }
    if step in field_limits:
        value = text.strip()
        if not value:
            send_message(
                user_id,
                "Введите текст или нажмите «Пропустить»."
            )
            return
        if len(value) > field_limits[step]:
            send_message(
                user_id,
                f"Слишком длинный ответ. Максимум для этого поля — {field_limits[step]} символов."
            )
            return
        state[step] = value
        advance_optional_lead_field(user_id, step)
        return

    if step == "photos":
        send_message(
            user_id,
            "Отправьте фотографию объекта или нажмите «Готово» / «Пропустить фотографии»."
        )
        return

    if step == "notify_retry":
        send_message(
            user_id,
            "Заявка уже сохранена. Нажмите кнопку «Повторить отправку», "
            "чтобы снова уведомить менеджера."
        )


# =========================================================
# ОБРАБОТКА КНОПОК
# =========================================================

def handle_button(user_id, payload):
    uid = str(user_id)

    if payload == "menu":
        main_menu(user_id)
        return

    if payload == "history":
        show_order_history(user_id)
        return

    if payload.startswith("history_view:"):
        try:
            order_id = int(payload.split(":", 1)[1])
        except ValueError:
            send_message(user_id, "Некорректный номер заказа.")
            return
        show_history_order(user_id, order_id)
        return

    if payload.startswith("lead_skip:"):
        field = payload.split(":", 1)[1]
        skip_optional_lead_field(user_id, field)
        return

    if payload == "lead_photos_done":
        state = lead_states.get(uid)
        if not state or state.get("step") != "photos":
            send_message(user_id, "Этап добавления фотографий уже завершён.")
            return
        finalize_lead(user_id)
        return

    if payload == "lead_skip_photos":
        state = lead_states.get(uid)
        if not state or state.get("step") != "photos":
            send_message(user_id, "Этап добавления фотографий уже завершён.")
            return
        state["photos"] = []
        finalize_lead(user_id)
        return

    if payload == "lead_retry_notification":
        state = lead_states.get(uid)
        if not state or state.get("step") != "notify_retry":
            send_message(user_id, "Нет уведомления, которое нужно повторить.")
            return
        finalize_lead(user_id)
        return

    if payload == "admin_panel":
        show_admin_panel(user_id)
        return

    if payload == "admin_orders":
        show_admin_orders(user_id)
        return

    if payload == "admin_orders_new":
        show_admin_orders(user_id, only_new=True)
        return

    if payload == "admin_orders_work":
        show_admin_orders(user_id, status="В работе")
        return

    if payload == "admin_orders_done":
        show_admin_archive(user_id, only_completed=True)
        return

    if payload == "admin_archive":
        show_admin_archive(user_id)
        return

    if payload.startswith("admin_archive_order:"):
        try:
            order_id = int(payload.split(":", 1)[1])
        except ValueError:
            send_message(user_id, "Некорректный номер заявки.")
            return
        show_admin_order(user_id, order_id, from_archive=True)
        return

    if payload == "admin_search":
        start_admin_search(user_id)
        return

    if payload == "admin_search_cancel":
        admin_search_states.discard(uid)
        show_admin_panel(user_id)
        return

    if payload.startswith("admin_order:"):
        try:
            order_id = int(payload.split(":", 1)[1])
        except ValueError:
            send_message(user_id, "Некорректный номер заявки.")
            return
        show_admin_order(user_id, order_id)
        return

    if payload.startswith("admin_delete_confirm:"):
        if not is_admin(user_id):
            send_message(user_id, "⛔ Доступ запрещён.")
            return

        try:
            order_id = int(payload.split(":", 1)[1])
        except ValueError:
            send_message(user_id, "Некорректный номер заявки.")
            return

        with sqlite3.connect(DB_FILE) as connection:
            row = connection.execute(
                "SELECT id, customer_name FROM customer_requests WHERE id = ?",
                (order_id,)
            ).fetchone()

        if not row:
            send_message(user_id, "Заявка не найдена.")
            return

        buttons = [
            [{
                "type": "callback",
                "text": "🗃 Да, в архив",
                "payload": f"admin_delete:{order_id}"
            }],
            [{
                "type": "callback",
                "text": "❌ Отмена",
                "payload": f"admin_order:{order_id}"
            }]
        ]

        send_message(
            user_id,
            f"🗃 ПЕРЕМЕЩЕНИЕ В АРХИВ\n\n"
            f"Переместить заявку №{order_id} ({row[1]}) из активных в архив?\n\n"
            "Все данные заявки сохранятся в базе бота и будут доступны в архиве.",
            buttons
        )
        return

    if payload.startswith("admin_status:"):
        try:
            _, order_id, status = payload.split(":", 2)
            set_admin_order_status(user_id, int(order_id), status)
        except ValueError:
            send_message(user_id, "Некорректные данные статуса.")
        return

    if payload.startswith("admin_delete:"):
        if not is_admin(user_id):
            send_message(user_id, "⛔ Доступ запрещён.")
            return

        try:
            order_id = int(payload.split(":", 1)[1])
        except ValueError:
            send_message(user_id, "Некорректный номер заявки.")
            return

        with sqlite3.connect(DB_FILE) as connection:
            cursor = connection.execute(
                "UPDATE customer_requests "
                "SET archived = 1, archive_reason = 'Перемещена администратором в архив' "
                "WHERE id = ? AND archived = 0",
                (order_id,)
            )
            found = cursor.rowcount > 0

        if found:
            try:
                sync_request_to_google(order_id)
            except Exception:
                logging.exception(
                    "Не удалось синхронизировать архивирование заявки №%s",
                    order_id
                )
            send_message(user_id, f"🗃 Заявка №{order_id} перемещена в архив. Данные сохранены.")
            show_admin_panel(user_id)
        else:
            send_message(user_id, "Активная заявка не найдена.")

        return

    if payload == "cancel":
        clear_user_data(uid)
        send_message(
            user_id,
            "Заказ отменён.",
            [[{
                "type": "callback",
                "text": "🏠 Главное меню",
                "payload": "menu"
            }]]
        )
        return

    if payload == "price":
        start_order(user_id)
        return

    if payload == "request_start":
        start_lead(
            user_id,
            "Заявка без предварительного расчёта. "
            "Детали заказа необходимо уточнить у клиента."
        )
        return

    if payload == "lead_start":
        state = lead_states.get(uid)

        if not state or not state.get("result"):
            send_message(
                user_id,
                "Сначала выполните расчёт стоимости или выберите заказ без расчёта."
            )
            return

        start_lead(user_id, state["result"])
        return

    if payload == "order_add_position":
        if uid not in order_states:
            send_message(user_id, "Сессия заказа не найдена. Начните новый расчёт.")
            return

        order_states[uid]["current"] = None
        ask_position_diameter(user_id)
        return

    if payload == "order_finish":
        if uid not in order_states or not order_states[uid]["positions"]:
            send_message(user_id, "Добавьте хотя бы одну позицию.")
            return

        ask_order_extras(user_id)
        return

    if payload.startswith("order_back:"):
        if uid not in order_states or not order_states[uid].get("current"):
            return

        target = payload.split(":", 1)[1]
        data = order_states[uid]["current"]

        if target == "diameter":
            order_states[uid]["current"] = None
            order_states[uid].pop("step", None)
            ask_position_diameter(user_id)
            return

        if target == "material":
            data["material"] = None
            data["depth"] = None
            data["quantity"] = 1
            data["conditions"] = set()
            data["height"] = None
            data["night"] = False
            order_states[uid].pop("step", None)
            ask_position_material(user_id)
            return

        if target == "depth":
            data["depth"] = None
            data["quantity"] = 1
            data["conditions"] = set()
            data["height"] = None
            data["night"] = False
            ask_position_depth(user_id)
            return

        if target == "quantity":
            data["quantity"] = 1
            data["conditions"] = set()
            data["height"] = None
            data["night"] = False
            ask_position_quantity(user_id)
            return

        return

    if payload.startswith("order_diam:"):
        if uid not in order_states:
            return

        diameter = int(payload.split(":", 1)[1])

        if diameter not in DIAMETERS:
            send_message(user_id, "Такого диаметра нет в тарифах.")
            return

        order_states[uid]["current"] = {
            "diameter": diameter,
            "material": None,
            "depth": None,
            "quantity": 1,
            "conditions": set(),
            "height": None,
            "night": False
        }

        ask_position_material(user_id)
        return

    if payload.startswith("order_material:"):
        if uid not in order_states or not order_states[uid].get("current"):
            return

        material = payload.split(":", 1)[1]

        if material not in ("Кирпич", "Бетон", "Армированный бетон"):
            return

        order_states[uid]["current"]["material"] = material
        ask_position_depth(user_id)
        return

    if payload.startswith("order_cond:"):
        if uid not in order_states or not order_states[uid].get("current"):
            return

        key = payload.split(":", 1)[1]
        if key not in COEFFICIENTS:
            return

        selected = order_states[uid]["current"]["conditions"]

        if key in selected:
            selected.remove(key)
        else:
            selected.add(key)

        ask_position_conditions(user_id)
        return

    if payload.startswith("order_height:"):
        if uid not in order_states or not order_states[uid].get("current"):
            return

        key = payload.split(":", 1)[1]
        if key not in HEIGHTS:
            return

        data = order_states[uid]["current"]
        data["height"] = None if data["height"] == key else key

        ask_position_conditions(user_id)
        return

    if payload == "order_night":
        if uid not in order_states or not order_states[uid].get("current"):
            return

        data = order_states[uid]["current"]
        data["night"] = not data["night"]

        ask_position_conditions(user_id)
        return

    if payload == "order_save_position":
        if uid not in order_states:
            return

        data = order_states[uid].get("current")

        if not data:
            send_message(user_id, "Сначала заполните параметры позиции.")
            return

        if (
            not data.get("material")
            or not data.get("depth")
            or not data.get("quantity")
        ):
            send_message(
                user_id,
                "Не все параметры заполнены. Проверьте материал, глубину и количество."
            )
            return

        order_states[uid]["positions"].append(deepcopy(data))
        order_states[uid]["current"] = None
        order_states[uid].pop("step", None)

        ask_after_position(user_id)
        return

    if payload.startswith("order_extra:"):
        if uid not in order_states:
            return

        key = payload.split(":", 1)[1]
        if key not in EXTRAS:
            return

        selected = order_states[uid]["extras"]

        if key in selected:
            selected.remove(key)
        else:
            selected.add(key)

        ask_order_extras(user_id)
        return

    if payload == "order_calculate":
        calculate_order(user_id)
        return

    if payload == "services":
        send_message(
            user_id,
            "🔹 Наши услуги\n\n"
            "Выполняем алмазное бурение отверстий "
            "в бетоне, кирпиче и армированном бетоне.\n"
            "Бетон не режем — выполняем только бурение отверстий."
        )
        return

    if payload == "location":
        send_message(
            user_id,
            "📍 География работ\n\n"
            "Санкт-Петербург и Ленинградская область."
        )
        return

    if payload == "contact":
        send_message(
            user_id,
            "📞 Связь с нами\n\n"
            "Оставьте заявку через кнопку «Заказать без расчёта» "
            "или выполните расчёт и отправьте его менеджеру."
        )
        return


# =========================================================
# ОБРАБОТКА СОБЫТИЙ MAX
# =========================================================

def handle_update(update):
    update_type = update.get("update_type")
    logging.info("Получено событие MAX: %s", update_type)

    if update_type == "bot_added":
        if not update.get("is_channel", False):
            logging.info(
                "Бот добавлен в групповой чат. chat_id=%s. "
                "Для привязки отправьте администратором команду %s",
                update.get("chat_id"), WORK_GROUP_BIND_COMMAND
            )
        return

    if update_type == "bot_removed":
        removed_chat_id = update.get("chat_id")
        if removed_chat_id and str(get_work_group_chat_id()) == str(removed_chat_id):
            clear_work_group_chat_id(removed_chat_id)
            logging.warning("Бот удалён из рабочей группы; привязка очищена")
        return

    if update_type == "bot_started":
        user_id = update.get("user", {}).get("user_id")
        if user_id:
            main_menu(user_id)
        return

    if update_type == "message_callback":
        callback = update.get("callback", {})
        user = callback.get("user", {})
        user_id = user.get("user_id")
        payload = callback.get("payload", "")

        if user_id and payload:
            handle_button(user_id, payload)
        return

    if update_type != "message_created":
        return

    message = update.get("message", {})
    sender = message.get("sender", {})
    recipient = message.get("recipient", {})
    user_id = sender.get("user_id")
    message_body = message.get("body") or {}
    text = message_body.get("text", "")
    attachments = message_body.get("attachments") or []
    text = str(text or "").strip()

    # Сообщения рабочей группы не должны попадать в личный сценарий клиента.
    if recipient.get("chat_type") == "chat":
        chat_id = recipient.get("chat_id") or update.get("chat_id")
        command = text.casefold()
        if (
            user_id is not None
            and ADMIN_USER_ID
            and str(user_id) == str(ADMIN_USER_ID)
            and command == WORK_GROUP_BIND_COMMAND.casefold()
        ):
            if not chat_id:
                logging.error("Не удалось определить chat_id рабочей группы")
                return
            try:
                # Проверяем возможность отправки до сохранения ID группы.
                send_group_message(
                    chat_id,
                    "✅ Рабочая группа подключена к боту «Алмазное бурение».\n"
                    "Новые заявки будут автоматически появляться здесь."
                )
                set_work_group_chat_id(chat_id)
                logging.info("Рабочая группа успешно привязана: chat_id=%s", chat_id)
                sync_pending_group_notifications()
            except Exception:
                logging.exception("Не удалось подключить рабочую группу chat_id=%s", chat_id)
        return

    logging.info("ID пользователя MAX: %s", user_id)

    if not user_id:
        return

    uid = str(user_id)

    # Во время шага фотографий изображения принимаются как вложения MAX.
    lead_state = lead_states.get(uid)
    if lead_state and lead_state.get("step") == "photos":
        image_attachments = [
            item for item in attachments
            if isinstance(item, dict) and item.get("type") == "image"
        ]
        if image_attachments:
            process_lead_photo_message(user_id, image_attachments)
        else:
            process_lead_message(user_id, text)
        return

    # Поисковый запрос администратора обрабатываем до остальных текстовых сценариев.
    if uid in admin_search_states:
        process_admin_search(user_id, text)
        return

    # Сначала обрабатываем ввод глубины и количества в калькуляторе.
    if uid in order_states:
        state = order_states[uid]
        step = state.get("step")

        if step == "depth":
            try:
                depth = float(text.replace(",", "."))

                if depth <= 0 or depth > 500:
                    raise ValueError

                state["current"]["depth"] = depth
                ask_position_quantity(user_id)

            except (ValueError, AttributeError):
                send_message(
                    user_id,
                    "Введите корректную глубину числом от 0 до 500 см. "
                    "Например: 30"
                )

            return

        if step == "quantity":
            try:
                quantity = int(text)

                if quantity <= 0 or quantity > 100000:
                    raise ValueError

                state["current"]["quantity"] = quantity
                state.pop("step", None)
                ask_position_conditions(user_id)

            except (ValueError, TypeError):
                send_message(
                    user_id,
                    "Введите количество целым числом от 1 до 100000. "
                    "Например: 5"
                )

            return

    # Затем обрабатываем имя, телефон и необязательные поля заявки.
    if uid in lead_states:
        state = lead_states[uid]

        if state.get("step") == "ready":
            send_message(
                user_id,
                "💎  АЛМАЗНОЕ БУРЕНИЕ\n"
                "━━━━━━━━━━━━━━━━━━\n\n"
                "📋 Ваш расчёт готов!\n\n"
                "Чтобы оставить заявку и получить консультацию "
                "менеджера, нажмите кнопку «Оставить заявку» "
                "под результатом расчёта."
            )
            return

        process_lead_message(user_id, text)
        return
    # Если пользователь написал произвольный текст вне сценария,
    # показываем главное меню.
    main_menu(user_id)

# =========================================================
# FLASK WEBHOOK
# =========================================================

@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "ok"}), 200


@app.route("/webhook", methods=["POST"])
def webhook():
    received_secret = request.headers.get(
        "X-Max-Bot-Api-Secret",
        ""
    )

    if not hmac.compare_digest(received_secret, WEBHOOK_SECRET):
        return jsonify({"error": "Unauthorized"}), 401

    update = request.get_json(silent=True)

    if not isinstance(update, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    try:
        handle_update(update)
    except Exception:
        logging.exception("Ошибка обработки Webhook")
        return jsonify({"error": "Processing failed"}), 500

    return jsonify({"ok": True}), 200


# =========================================================
# РЕГИСТРАЦИЯ WEBHOOK
# =========================================================

def register_webhook():
    time.sleep(3)

    payload = {
        "url": WEBHOOK_URL,
        "update_types": [
            "bot_added",
            "bot_removed",
            "bot_started",
            "message_created",
            "message_callback"
        ],
        "secret": WEBHOOK_SECRET
    }

    try:
        response = session.post(
            f"{API_URL}/subscriptions",
            headers=HEADERS,
            json=payload,
            timeout=20
        )

        logging.info(
            "Регистрация Webhook: %s %s",
            response.status_code,
            response.text
        )
        response.raise_for_status()

        if response.json().get("success"):
            logging.info("Webhook успешно зарегистрирован")

    except Exception:
        logging.exception("Не удалось зарегистрировать Webhook")


if __name__ == "__main__":
    PORT = int(os.getenv("PORT", "3000"))

    logging.info(
        "Запускаем Webhook-сервер на порту %s",
        PORT
    )

    threading.Thread(
        target=register_webhook,
        daemon=True
    ).start()

    threading.Thread(
        target=sync_all_requests_to_google,
        daemon=True
    ).start()

    threading.Thread(
        target=sync_pending_group_notifications,
        daemon=True
    ).start()

    app.run(
        host="0.0.0.0",
        port=PORT,
        threaded=True
    )
    
