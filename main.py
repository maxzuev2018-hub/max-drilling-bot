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
from pathlib import Path
from copy import deepcopy

import requests
from flask import Flask, request, jsonify
from requests.adapters import HTTPAdapter


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

# Постоянные расчёты и заявки хранятся в общем хранилище Bothost.
# После подключения общего хранилища путь /app/shared сохраняется
# между обновлениями и перезапусками приложения.
SHARED_DIR = Path("/app/shared")
SHARED_DIR.mkdir(parents=True, exist_ok=True)
DB_FILE = SHARED_DIR / "orders_history.sqlite3"
logging.info("База заказов и заявок: %s", DB_FILE)


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
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_customer_requests_status "
            "ON customer_requests(status, id DESC)"
        )


def save_order_history(user_id, total, result):
    with sqlite3.connect(DB_FILE) as connection:
        connection.execute(
            "INSERT INTO order_history (user_id, created_at, total, result) "
            "VALUES (?, ?, ?, ?)",
            (str(user_id), datetime.now().strftime("%d.%m.%Y %H:%M"), float(total), result)
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


def save_customer_request(user_id, customer_name, phone, result):
    with sqlite3.connect(DB_FILE) as connection:
        cursor = connection.execute(
            "INSERT INTO customer_requests "
            "(user_id, created_at, customer_name, phone, result, status) "
            "VALUES (?, ?, ?, ?, ?, 'Новая')",
            (str(user_id), datetime.now().strftime("%d.%m.%Y %H:%M"),
             customer_name, phone, result)
        )
        return cursor.lastrowid


def show_admin_panel(user_id):
    if not is_admin(user_id):
        send_message(user_id, "⛔ Доступ запрещён.")
        return
    with sqlite3.connect(DB_FILE) as connection:
        total = connection.execute("SELECT COUNT(*) FROM customer_requests").fetchone()[0]
        new_count = connection.execute(
            "SELECT COUNT(*) FROM customer_requests WHERE status = 'Новая'"
        ).fetchone()[0]
        work_count = connection.execute(
            "SELECT COUNT(*) FROM customer_requests WHERE status = 'В работе'"
        ).fetchone()[0]
        done_count = connection.execute(
            "SELECT COUNT(*) FROM customer_requests WHERE status = 'Завершена'"
        ).fetchone()[0]
    buttons = [
        [{"type": "callback", "text": "📥 Все заявки", "payload": "admin_orders"}],
        [{"type": "callback", "text": "🆕 Новые заявки", "payload": "admin_orders_new"}],
        [{"type": "callback", "text": "🔧 Заявки в работе", "payload": "admin_orders_work"}],
        [{"type": "callback", "text": "✅ Завершённые", "payload": "admin_orders_done"}],
        [{"type": "callback", "text": "🔎 Поиск по имени или телефону", "payload": "admin_search"}],
        [{"type": "callback", "text": "🏠 Главное меню", "payload": "menu"}],
    ]
    send_message(
        user_id,
        f"🛠 АДМИН-ПАНЕЛЬ\n\nВсего заявок: {total}\nНовых: {new_count}\n"
        f"В работе: {work_count}\nЗавершённых: {done_count}",
        buttons
    )


def show_admin_orders(user_id, only_new=False, status=None, search_term=None):
    if not is_admin(user_id):
        send_message(user_id, "⛔ Доступ запрещён.")
        return

    if only_new:
        status = "Новая"
    conditions = []
    params = []
    if status:
        conditions.append("status = ?")
        params.append(status)
    if search_term:
        conditions.append("(customer_name LIKE ? OR phone LIKE ? OR CAST(id AS TEXT) LIKE ?)")
        pattern = f"%{search_term}%"
        params.extend([pattern, pattern, pattern])

    query = (
        "SELECT id, created_at, customer_name, phone, status "
        "FROM customer_requests"
    )
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT 20"

    with sqlite3.connect(DB_FILE) as connection:
        rows = connection.execute(query, params).fetchall()

    if search_term:
        title = f"🔎 РЕЗУЛЬТАТЫ ПОИСКА: {search_term}"
    elif status == "Новая":
        title = "🆕 НОВЫЕ ЗАЯВКИ"
    elif status == "В работе":
        title = "🔧 ЗАЯВКИ В РАБОТЕ"
    elif status == "Завершена":
        title = "✅ ЗАВЕРШЁННЫЕ ЗАЯВКИ"
    else:
        title = "📋 ВСЕ ЗАЯВКИ"

    if not rows:
        buttons = [
            [{"type": "callback", "text": "🔎 Новый поиск", "payload": "admin_search"}],
            [{"type": "callback", "text": "⬅️ В админ-панель", "payload": "admin_panel"}],
        ]
        send_message(user_id, f"{title}\n\nНичего не найдено.", buttons)
        return

    lines = [title, "", "Показаны последние 20 подходящих заявок:"]
    buttons = []
    for order_id, created_at, name, phone, order_status in rows:
        lines.append(f"№{order_id} — {name} — {order_status} — {created_at}")
        buttons.append([{
            "type": "callback",
            "text": f"Открыть заявку №{order_id}",
            "payload": f"admin_order:{order_id}"
        }])
    buttons.extend([
        [{"type": "callback", "text": "🔎 Поиск", "payload": "admin_search"}],
        [{"type": "callback", "text": "⬅️ В админ-панель", "payload": "admin_panel"}],
    ])
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


def show_admin_order(user_id, order_id):
    if not is_admin(user_id):
        send_message(user_id, "⛔ Доступ запрещён.")
        return
    with sqlite3.connect(DB_FILE) as connection:
        row = connection.execute(
            "SELECT user_id, created_at, customer_name, phone, result, status "
            "FROM customer_requests WHERE id = ?", (int(order_id),)
        ).fetchone()
    if not row:
        send_message(user_id, "Заявка не найдена.")
        return
    client_id, created_at, name, phone, result, status = row
    buttons = [
        [{"type": "callback", "text": "🆕 Новая", "payload": f"admin_status:{order_id}:Новая"}],
        [{"type": "callback", "text": "🔧 В работе", "payload": f"admin_status:{order_id}:В работе"}],
        [{"type": "callback", "text": "✅ Завершена", "payload": f"admin_status:{order_id}:Завершена"}],
        [{"type": "callback", "text": "⬅️ К списку заявок", "payload": "admin_orders"}],
    ]
    send_message(user_id,
        f"📋 ЗАЯВКА №{order_id}\nДата: {created_at}\nСтатус: {status}\n\n"
        f"Имя: {name}\nТелефон: {phone}\nID клиента MAX: {client_id}\n\n{result}",
        buttons)


def set_admin_order_status(user_id, order_id, status):
    if not is_admin(user_id):
        send_message(user_id, "⛔ Доступ запрещён.")
        return
    if status not in ("Новая", "В работе", "Завершена"):
        send_message(user_id, "Недопустимый статус.")
        return
    with sqlite3.connect(DB_FILE) as connection:
        cursor = connection.execute(
            "UPDATE customer_requests SET status = ? WHERE id = ?",
            (status, int(order_id))
        )
    if cursor.rowcount:
        send_message(user_id, f"✅ Статус заявки №{order_id} изменён: {status}")
        show_admin_order(user_id, order_id)
    else:
        send_message(user_id, "Заявка не найдена.")


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

def send_message(user_id, text, buttons=None):
    body = {"text": text}

    if buttons:
        body["attachments"] = [{
            "type": "inline_keyboard",
            "payload": {"buttons": buttons}
        }]

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


def notify_admin(text):
    if not ADMIN_USER_ID:
        logging.error("Не задан ADMIN_USER_ID")
        return

    send_message(ADMIN_USER_ID, text)


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
            "text": "🔹 Рассчитать стоимость",
            "payload": "price"
        }],
        [{
            "type": "callback",
            "text": "📩 Заказать без расчёта",
            "payload": "request_start"
        }],
        [{
            "type": "callback",
            "text": "🔹 Наши услуги",
            "payload": "services"
        }],
        [{
            "type": "callback",
            "text": "🔹 География работ",
            "payload": "location"
        }],
        [{
            "type": "callback",
            "text": "📋 История заказов",
            "payload": "history"
        }],
        [{
            "type": "callback",
            "text": "🔹 Связаться с нами",
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
        "Здравствуйте! 👋\n\n"
        "Вы обратились в службу «MAX Алмазное бурение».\n\n"
        "Выполняем алмазное бурение отверстий "
        "в бетоне, кирпиче и армированном бетоне "
        "в Санкт-Петербурге и Ленинградской области.\n\n"
        "Выберите, что вас интересует:",
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
        (f"{diameter} мм", f"order_diam:{diameter}")
        for diameter in DIAMETERS
    ]
    items.append(("Отмена заказа", "cancel"))

    send_message(
        user_id,
        f"🔹 НОВЫЙ ЗАКАЗ\n\n"
        f"Позиция №{position_number}\n\n"
        "Выберите диаметр отверстия:",
        keyboard(items)
    )


def ask_position_material(user_id):
    items = [
        ("Кирпич", "order_material:Кирпич"),
        ("Бетон", "order_material:Бетон"),
        ("Армированный бетон", "order_material:Армированный бетон"),
        ("⬅️ Назад к диаметру", "order_back:diameter"),
        ("Отмена заказа", "cancel"),
    ]

    send_message(
        user_id,
        "Выберите материал стены:",
        keyboard(items, 1)
    )


def ask_position_depth(user_id):
    uid = str(user_id)
    order_states[uid]["step"] = "depth"

    send_message(
        user_id,
        "Введите глубину одного отверстия в сантиметрах.\n\n"
        "Например: 30\n\n"
        "Можно использовать запятую или точку.",
        [[
            {"type": "callback", "text": "⬅️ Назад к материалу", "payload": "order_back:material"},
            {"type": "callback", "text": "Отмена заказа", "payload": "cancel"}
        ]]
    )


def ask_position_quantity(user_id):
    uid = str(user_id)
    order_states[uid]["step"] = "quantity"

    send_message(
        user_id,
        "Сколько одинаковых отверстий с такими параметрами нужно пробурить?\n\n"
        "Введите количество целым числом.\n"
        "Например: 5",
        [[
            {"type": "callback", "text": "⬅️ Назад к глубине", "payload": "order_back:depth"},
            {"type": "callback", "text": "Отмена заказа", "payload": "cancel"}
        ]]
    )


def ask_position_conditions(user_id):
    uid = str(user_id)
    state = order_states[uid]
    data = state["current"]

    lines = [
        "Условия бурения для позиции "
        f"№{len(state['positions']) + 1}:",
        "",
        "Нажимайте кнопки, чтобы включить или выключить условия.",
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
    items.append((night_mark + "Ночное время (20:00–8:00)", "order_night"))

    if data["conditions"] or data["height"] or data["night"]:
        lines.append("Выбранные условия:")
        for key in data["conditions"]:
            name, factor = COEFFICIENTS[key]
            lines.append(f"• {name}: ×{factor}")

        if data["height"]:
            name, factor = HEIGHTS[data["height"]]
            lines.append(f"• {name}: ×{factor}")

        if data["night"]:
            lines.append("• Ночное время: ×1,5 на весь заказ")

    items.append(("⬅️ Назад к количеству", "order_back:quantity"))
    items.append(("💾 Сохранить позицию", "order_save_position"))
    items.append(("Отмена заказа", "cancel"))

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
        ("Отмена заказа", "cancel"),
    ]

    send_message(
        user_id,
        f"Позиция сохранена! ✅\n\n"
        f"В заказе сейчас позиций: {count}.\n\n"
        "Что будем делать дальше?",
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
        ("Отмена заказа", "cancel"),
    ])

    send_message(
        user_id,
        "Дополнительные услуги для всего заказа.\n\n"
        "Отметьте необходимые услуги. "
        "Каждая выбранная услуга учитывается один раз на весь заказ.",
        keyboard(items, 1)
    )


def calculate_order(user_id):
    uid = str(user_id)
    state = order_states.get(uid)

    if not state or not state["positions"]:
        send_message(user_id, "В заказе пока нет ни одной позиции.")
        return

    lines = ["💰 ПРЕДВАРИТЕЛЬНЫЙ РАСЧЁТ ЗАКАЗА", ""]
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
            f"ПОЗИЦИЯ №{index}",
            f"Диаметр: {diameter} мм",
            f"Материал: {material}",
            f"Глубина одного отверстия: {depth:g} см",
            f"Количество: {quantity}",
            f"Цена за 1 см: {rate} ₽",
            f"Стоимость одного отверстия: {one_hole_price:.2f} ₽",
            f"Стоимость позиции: {position_total:.2f} ₽",
        ])

        if details:
            lines.append("Условия: " + "; ".join(details))

        if position.get("night"):
            lines.append(
                "Ночное время выбрано: коэффициент будет применён ко всему заказу."
            )

        lines.append("")

    if has_night:
        before_night = drilling_subtotal
        drilling_subtotal *= 1.5
        lines.extend([
            "Ночной коэффициент применён один раз ко всему бурению заказа: ×1,5",
            f"Бурение до ночного коэффициента: {before_night:.2f} ₽",
            f"Бурение с ночным коэффициентом: {drilling_subtotal:.2f} ₽",
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

    lines.append(f"ИТОГО бурение: {drilling_subtotal:.2f} ₽")

    if extra_lines:
        lines.append("")
        lines.append("ДОПОЛНИТЕЛЬНЫЕ УСЛУГИ:")
        lines.extend(extra_lines)
        lines.append(f"Стоимость услуг с фиксированной ценой: {extra_total:.2f} ₽")

    lines.extend([
        "",
        f"ОБЩАЯ СТОИМОСТЬ: {total:.2f} ₽",
        "",
        "Это предварительный расчёт. Окончательная стоимость "
        "уточняется после согласования деталей заказа."
    ])

    if "waste" in state["extras"]:
        lines.append(
            "Вывоз мусора оплачивается отдельно по договорённости."
        )

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
        result + "\n\nХотите оставить заявку?",
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
        "result": result
    }

    send_message(user_id, "Как вас зовут?")


def ask_lead_phone(user_id):
    uid = str(user_id)
    lead_states[uid]["step"] = "phone"

    send_message(
        user_id,
        "📞 Теперь отправьте номер телефона.\n"
        "Например: +79991234567"
    )


def process_lead_message(user_id, text):
    uid = str(user_id)
    state = lead_states[uid]

    if state["step"] == "name":
        name = text.strip()

        if len(name) < 2:
            send_message(user_id, "Пожалуйста, введите имя.")
            return

        state["name"] = name
        ask_lead_phone(user_id)
        return

    if state["step"] == "phone":
        phone = text.strip()
        digits = "".join(filter(str.isdigit, phone))

        if len(digits) < 10 or len(digits) > 15:
            send_message(
                user_id,
                "Пожалуйста, введите корректный номер телефона."
            )
            return

        request_id = save_customer_request(
            user_id, state["name"], phone, state["result"]
        )
        admin_message = (
            f"📩 НОВАЯ ЗАЯВКА №{request_id}!\n\n"
            f"Имя: {state['name']}\n"
            f"Телефон: {phone}\n"
            f"ID клиента MAX: {user_id}\n\n"
            f"{state['result']}\n\n"
            "Откройте админ-панель бота, чтобы изменить статус заявки."
        )

        try:
            notify_admin(admin_message)
        except Exception:
            logging.exception("Не удалось отправить заявку администратору")
            send_message(
                user_id,
                "Не удалось отправить заявку автоматически. "
                "Пожалуйста, попробуйте позже или свяжитесь с нами напрямую."
            )
            return

        lead_states.pop(uid, None)

        send_message(
            user_id,
            "✅ Спасибо! Ваша заявка отправлена.\n"
            "Мы свяжемся с вами в ближайшее время.",
            [[{
                "type": "callback",
                "text": "🏠 Главное меню",
                "payload": "menu"
            }]]
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
        show_admin_orders(user_id, status="Завершена")
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

    if payload.startswith("admin_status:"):
        try:
            _, order_id, status = payload.split(":", 2)
            set_admin_order_status(user_id, int(order_id), status)
        except ValueError:
            send_message(user_id, "Некорректные данные статуса.")
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
    user_id = sender.get("user_id")
    text = message.get("body", {}).get("text", "")

    logging.info("ID пользователя MAX: %s", user_id)

    if not user_id:
        return

    uid = str(user_id)
    text = text.strip()

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

                if depth <= 0 or depth > 10000:
                    raise ValueError

                state["current"]["depth"] = depth
                ask_position_quantity(user_id)

            except (ValueError, AttributeError):
                send_message(
                    user_id,
                    "Введите корректную глубину числом от 0 до 10000 см. "
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

    # Затем обрабатываем имя и телефон заявки.
    if uid in lead_states:
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

    app.run(
        host="0.0.0.0",
        port=PORT,
        threaded=True
    )
