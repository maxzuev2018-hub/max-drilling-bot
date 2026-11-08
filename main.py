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

if not TOKEN:
    raise RuntimeError("Не задан MAX_TOKEN в Bothost")

if not WEBHOOK_SECRET:
    raise RuntimeError("Не задан MAX_WEBHOOK_SECRET в Bothost")

if not re.fullmatch(r"[A-Za-z0-9_-]{5,256}", WEBHOOK_SECRET):
    raise RuntimeError(
        "Секрет содержит недопустимые символы. "
        "Используйте латинские буквы, цифры, _ и -"
    )

API_URL = "https://platform-api2.max.ru"
HEADERS = {"Authorization": TOKEN}

WEBHOOK_URL = (
    "https://bot-1794067708-7548-maksim-z.bothost.tech/webhook"
)

# Проверка сертификата MAX
CA_FILE = (
    Path(__file__).resolve().parent
    / "russian_trusted_sub_ca_2024.pem"
)

EXPECTED_SHA256 = (
    "2155785036c900dbb5f1bb2a1569c80c"
    "55595bd6bf94867a29bbddbc7d88a3f2"
)

if not CA_FILE.exists():
    raise FileNotFoundError(f"Не найден сертификат: {CA_FILE}")

pem_data = CA_FILE.read_text(encoding="ascii")
der_data = ssl.PEM_cert_to_DER_cert(pem_data)
actual_hash = hashlib.sha256(der_data).hexdigest()

if actual_hash != EXPECTED_SHA256:
    raise RuntimeError("Отпечаток сертификата не совпадает!")

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


# Отправка сообщения пользователю
def send_message(user_id, text, buttons=None):
    body = {"text": text}

    if buttons:
        body["attachments"] = [
            {
                "type": "inline_keyboard",
                "payload": {"buttons": buttons}
            }
        ]

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


# Главное меню
def send_menu(user_id):
    buttons = [
        [
            {
                "type": "callback",
                "text": "🔹 Рассчитать стоимость",
                "payload": "price"
            }
        ],
        [
            {
                "type": "callback",
                "text": "🔹 Наши услуги",
                "payload": "services"
            }
        ],
        [
            {
                "type": "callback",
                "text": "🔹 География работ",
                "payload": "location"
            }
        ],
        [
            {
                "type": "callback",
                "text": "🔹 Связаться с нами",
                "payload": "contact"
            }
        ]
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


# Обработка нажатий на кнопки
def handle_button(user_id, payload):
    if payload == "price":
        send_message(
            user_id,
            "💰 Расчёт стоимости бурения.\n\n"
            "Скоро здесь можно будет выбрать диаметр отверстия, "
            "материал стены и глубину бурения.\n\n"
            "Калькулятор подготовим следующим этапом."
        )

    elif payload == "services":
        send_message(
            user_id,
            "🔹 Наши услуги\n\n"
            "Выполняем алмазное бурение отверстий "
            "в бетоне, кирпиче и других материалах."
        )

    elif payload == "location":
        send_message(
            user_id,
            "📍 География работ\n\n"
            "Санкт-Петербург и Ленинградская область."
        )

    elif payload == "contact":
        send_message(
            user_id,
            "📞 Связь с нами\n\n"
            "Напишите, какое отверстие вам необходимо "
            "просверлить, и мы свяжемся с вами."
        )


# Обработка события от MAX
def handle_update(update):
    update_type = update.get("update_type")

    logging.info("Получено событие MAX: %s", update_type)

    # Пользователь впервые запустил бота
    if update_type == "bot_started":
        user = update.get("user", {})
        user_id = user.get("user_id")

        if user_id:
            logging.info("Первый запуск бота пользователем")
            send_menu(user_id)

    # Пользователь написал сообщение
    elif update_type == "message_created":
        message = update.get("message", {})
        sender = message.get("sender", {})
        user_id = sender.get("user_id")
        text = message.get("body", {}).get("text", "")

        if user_id and text:
            send_menu(user_id)

    # Пользователь нажал кнопку
    elif update_type == "message_callback":
        callback = update.get("callback", {})
        user = callback.get("user", {})
        user_id = user.get("user_id")
        payload = callback.get("payload", "")

        if user_id and payload:
            handle_button(user_id, payload)


# Проверка доступности сервера
@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "ok"}), 200


# Приём событий MAX
@app.route("/webhook", methods=["POST"])
def webhook():
    received_secret = request.headers.get(
        "X-Max-Bot-Api-Secret", ""
    )

    if not hmac.compare_digest(
        received_secret, WEBHOOK_SECRET
    ):
        logging.warning("Неверный секрет Webhook")
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


# Регистрация Webhook в MAX
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

        result = response.json()

        if result.get("success"):
            logging.info("Webhook успешно зарегистрирован")
        else:
            logging.error("MAX не подтвердил регистрацию Webhook")

    except Exception:
        logging.exception("Не удалось зарегистрировать Webhook")


if __name__ == "__main__":
    PORT = int(os.getenv("PORT", "3000"))

    logging.info("Запускаем Webhook-сервер на порту %s", PORT)

    threading.Thread(
        target=register_webhook,
        daemon=True
    ).start()

    app.run(
        host="0.0.0.0",
        port=PORT,
        threaded=True
    )
