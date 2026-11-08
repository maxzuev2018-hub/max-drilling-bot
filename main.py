import os
import re
import time
import ssl
import hmac
import hashlib
import logging
import threading
from pathlib import Path

import requests
from flask import Flask, request, jsonify
from requests.adapters import HTTPAdapter

logging.basicConfig(level=logging.INFO)

TOKEN = os.getenv("MAX_TOKEN")
WEBHOOK_SECRET = os.getenv("MAX_WEBHOOK_SECRET")

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

# Временные данные расчётов пользователей
calculations = {}

# Тарифы: рубли за 1 см
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

COEFFICIENTS = {
    "angle": ("Бурение под углом", 1.3),
    "cold": ("Температура от 0 до -5 °C", 1.5),
    "night": ("Ночное время (20:00–8:00)", 1.5),
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

    logging.info("Ответ MAX: %s %s", response.status_code, response.text)
    response.raise_for_status()


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


def main_menu(user_id):
    calculations.pop(str(user_id), None)

    buttons = [
        [{"type": "callback", "text": "🔹 Рассчитать стоимость", "payload": "price"}],
        [{"type": "callback", "text": "🔹 Наши услуги", "payload": "services"}],
        [{"type": "callback", "text": "🔹 География работ", "payload": "location"}],
        [{"type": "callback", "text": "🔹 Связаться с нами", "payload": "contact"}],
    ]

    send_message(
        user_id,
        "Здравствуйте! 👋\n\n"
        "Вы обратились в службу «MAX Алмазное бурение».\n\n"
        "Выполняем алмазное бурение отверстий "
        "в Санкт-Петербурге и Ленинградской области.\n\n"
        "Выберите, что вас интересует:",
        buttons
    )


def ask_diameter(user_id):
    items = [
        (f"До {d} мм" if d == 40 else f"{d} мм", f"diam:{d}")
        for d in DIAMETERS
    ]
    items.append(("Отмена", "cancel"))

    send_message(
        user_id,
        "🔹 Шаг 1 из 3.\n\nВыберите диаметр отверстия:",
        keyboard(items)
    )


def ask_material(user_id):
    items = [
        ("Кирпич", "material:Кирпич"),
        ("Бетон", "material:Бетон"),
        ("Армированный бетон", "material:Армированный бетон"),
        ("Назад", "back_diameter"),
    ]

    send_message(
        user_id,
        "🔹 Шаг 2 из 3.\n\nВыберите материал стены:",
        keyboard(items)
    )


def ask_depth(user_id):
    send_message(
        user_id,
        "🔹 Шаг 3 из 3.\n\n"
        "Введите глубину бурения в сантиметрах.\n"
        "Например: 30",
        [[
            {"type": "callback", "text": "Назад", "payload": "back_material"},
            {"type": "callback", "text": "Отмена", "payload": "cancel"},
        ]]
    )


def ask_conditions(user_id):
    data = calculations[str(user_id)]
    selected = data["conditions"]
    height = data["height"]

    lines = ["Выберите дополнительные условия."]
    lines.append("Нажимайте на кнопки, чтобы отметить или снять условие.")
    lines.append("")

    for key, (name, factor) in COEFFICIENTS.items():
        mark = "✅ " if key in selected else ""
        lines.append(f"{mark}{name} — ×{factor}")

    for key, (name, factor) in HEIGHTS.items():
        mark = "✅ " if height == key else ""
        lines.append(f"{mark}{name} — ×{factor}")

    items = []

    for key, (name, factor) in COEFFICIENTS.items():
        mark = "✓ " if key in selected else ""
        items.append((mark + name, f"cond:{key}"))

    for key, (name, factor) in HEIGHTS.items():
        mark = "✓ " if height == key else ""
        items.append((mark + name, f"height:{key}"))

    items.append(("Далее к дополнительным услугам", "extras"))
    items.append(("Отмена", "cancel"))

    send_message(user_id, "\n".join(lines), keyboard(items, 1))


def ask_extras(user_id):
    selected = calculations[str(user_id)]["extras"]

    items = []
    for key, (name, price) in EXTRAS.items():
        mark = "✓ " if key in selected else ""
        price_text = "по договорённости" if price is None else f"{price} ₽"
        items.append((f"{mark}{name} ({price_text})", f"extra:{key}"))

    items.append(("Рассчитать стоимость", "calculate"))
    items.append(("Назад к условиям", "back_conditions"))
    items.append(("Отмена", "cancel"))

    send_message(
        user_id,
        "Дополнительные услуги.\n\n"
        "Отметьте нужные услуги и нажмите «Рассчитать стоимость».",
        keyboard(items, 1)
    )


def calculate(user_id):
    data = calculations[str(user_id)]

    diameter = data["diameter"]
    material = data["material"]
    depth = data["depth"]

    rate = DIAMETERS[diameter][material]
    base = rate * depth

    coefficient = 1.0
    details = []

    if depth > 50:
        coefficient *= 1.5
        details.append("Длина отверстия свыше 500 мм: ×1.5")

    for key in data["conditions"]:
        name, factor = COEFFICIENTS[key]
        coefficient *= factor
        details.append(f"{name}: ×{factor}")

    if data["height"]:
        name, factor = HEIGHTS[data["height"]]
        coefficient *= factor
        details.append(f"{name}: ×{factor}")

    drilling_price = round(base * coefficient, 2)

    extra_total = 0
    extra_lines = []

    for key in data["extras"]:
        name, price = EXTRAS[key]
        if price is None:
            extra_lines.append(f"{name}: стоимость согласуется с менеджером")
        else:
            extra_total += price
            extra_lines.append(f"{name}: {price} ₽")

    total = drilling_price + extra_total

    result = (
        "💰 ПРЕДВАРИТЕЛЬНЫЙ РАСЧЁТ\n\n"
        f"Диаметр: {diameter} мм\n"
        f"Материал: {material}\n"
        f"Глубина: {depth} см\n\n"
        f"Цена за 1 см: {rate} ₽\n"
        f"Базовая стоимость: {rate} × {depth} = {base} ₽\n"
        f"Общий коэффициент: ×{coefficient:.3f}\n"
    )

    if details:
        result += "\nДополнительные условия:\n"
        result += "\n".join(details) + "\n"

    result += f"\nСтоимость бурения: {drilling_price:.2f} ₽\n"

    if extra_lines:
        result += "\nДополнительные услуги:\n"
        result += "\n".join(extra_lines) + "\n"

    result += (
        f"\nИТОГО: {total:.2f} ₽\n\n"
        "Это предварительная стоимость. "
        "Окончательная цена уточняется после согласования деталей заказа."
    )

    if "waste" in data["extras"]:
        result += "\nВывоз мусора оплачивается отдельно по договорённости."

    send_message(
        user_id,
        result,
        [
            [{"type": "callback", "text": "🔄 Новый расчёт", "payload": "price"}],
            [{"type": "callback", "text": "🏠 Главное меню", "payload": "menu"}],
        ]
    )

    calculations.pop(str(user_id), None)


def handle_button(user_id, payload):
    uid = str(user_id)

    if payload == "menu":
        main_menu(user_id)
        return

    if payload == "cancel":
        calculations.pop(uid, None)
        send_message(user_id, "Расчёт отменён.", [
            [{"type": "callback", "text": "Главное меню", "payload": "menu"}]
        ])
        return

    if payload == "price":
        calculations[uid] = {
            "conditions": set(),
            "height": None,
            "extras": set()
        }
        ask_diameter(user_id)
        return

    if payload.startswith("diam:"):
        if uid not in calculations:
            calculations[uid] = {
                "conditions": set(),
                "height": None,
                "extras": set()
            }
        calculations[uid]["diameter"] = int(payload.split(":")[1])
        ask_material(user_id)
        return

    if payload.startswith("material:"):
        if uid not in calculations:
            return
        calculations[uid]["material"] = payload.split(":", 1)[1]
        ask_depth(user_id)
        return

    if payload == "back_diameter":
        ask_diameter(user_id)
        return

    if payload == "back_material":
        ask_material(user_id)
        return

    if payload.startswith("cond:"):
        key = payload.split(":")[1]
        data = calculations.get(uid)
        if data:
            if key in data["conditions"]:
                data["conditions"].remove(key)
            else:
                data["conditions"].add(key)
            ask_conditions(user_id)
        return

    if payload.startswith("height:"):
        key = payload.split(":")[1]
        data = calculations.get(uid)
        if data:
            data["height"] = None if data["height"] == key else key
            ask_conditions(user_id)
        return

    if payload == "extras":
        ask_extras(user_id)
        return

    if payload == "back_conditions":
        ask_conditions(user_id)
        return

    if payload.startswith("extra:"):
        key = payload.split(":")[1]
        data = calculations.get(uid)
        if data:
            if key in data["extras"]:
                data["extras"].remove(key)
            else:
                data["extras"].add(key)
            ask_extras(user_id)
        return

    if payload == "calculate":
        if uid in calculations:
            calculate(user_id)
        return

    if payload == "services":
        send_message(
            user_id,
            "🔹 Наши услуги\n\n"
            "Выполняем алмазное бурение отверстий "
            "в бетоне, кирпиче и других материалах."
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
            "Напишите, какое отверстие вам необходимо "
            "просверлить, и мы свяжемся с вами."
        )


def handle_update(update):
    update_type = update.get("update_type")
    logging.info("Получено событие MAX: %s", update_type)

    if update_type == "bot_started":
        user_id = update.get("user", {}).get("user_id")
        if user_id:
            main_menu(user_id)

    elif update_type == "message_created":
        message = update.get("message", {})
        sender = message.get("sender", {})
        user_id = sender.get("user_id")
        logging.info("ID пользователя MAX: %s", user_id)
        text = message.get("body", {}).get("text", "")

        if not user_id:
            return

        uid = str(user_id)

        if uid in calculations and "depth" not in calculations[uid]:
            try:
                depth = float(text.replace(",", ".").strip())
                if depth <= 0 or depth > 10000:
                    raise ValueError

                calculations[uid]["depth"] = depth
                ask_conditions(user_id)

            except (ValueError, AttributeError):
                send_message(
                    user_id,
                    "Пожалуйста, введите глубину числом в сантиметрах. "
                    "Например: 30"
                )
        else:
            main_menu(user_id)

    elif update_type == "message_callback":
        callback = update.get("callback", {})
        user = callback.get("user", {})
        user_id = user.get("user_id")
        payload = callback.get("payload", "")

        if user_id and payload:
            handle_button(user_id, payload)


@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "ok"}), 200


@app.route("/webhook", methods=["POST"])
def webhook():
    received_secret = request.headers.get("X-Max-Bot-Api-Secret", "")

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

    logging.info("Запускаем Webhook-сервер на порту %s", PORT)

    threading.Thread(target=register_webhook, daemon=True).start()

    app.run(host="0.0.0.0", port=PORT, threaded=True)
