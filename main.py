import os
import time
import logging
import ssl
import hashlib
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter

logging.basicConfig(level=logging.INFO)

TOKEN = os.getenv("MAX_TOKEN")

if not TOKEN:
    raise RuntimeError("Не задан MAX_TOKEN в переменных Bothost")

API_URL = "https://platform-api2.max.ru"
HEADERS = {"Authorization": TOKEN}

# Проверка сертификата MAX
CA_FILE = Path(__file__).resolve().parent / "russian_trusted_sub_ca_2024.pem"

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


# Обработка нажатий на кнопки
def handle_button(user_id, payload):
    if payload == "price":
        send_message(
            user_id,
            "💰 Расчёт стоимости бурения.\n\n"
            "Скоро здесь можно будет выбрать диаметр отверстия, "
            "материал стены и глубину бурения.\n\n"
            "Калькулятор стоимости подготовим следующим этапом."
        )

    elif payload == "services":
        send_message(
            user_id,
            "🔹 Наши услуги\n\n"
            "Выполняем алмазное бурение отверстий "
            "в бетоне, кирпиче и других материалах.\n\n"
            "Работаем с различными диаметрами и глубиной бурения."
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
            "Напишите здесь, какое отверстие вам необходимо "
            "просверлить, и мы свяжемся с вами."
        )

    elif payload == "menu":
        send_menu(user_id)


def main():
    marker = None
    logging.info("Бот запущен и ожидает сообщения")

    while True:
        try:
            params = {"timeout": 30}

            if marker is not None:
                params["marker"] = marker

            response = session.get(
                f"{API_URL}/updates",
                headers=HEADERS,
                params=params,
                timeout=40
            )

            response.raise_for_status()
            data = response.json()

            marker = data.get("marker", marker)

            for update in data.get("updates", []):

                # Обычное сообщение пользователя
                if update.get("update_type") == "message_created":
                    message = update.get("message", {})
                    sender = message.get("sender", {})
                    user_id = sender.get("user_id")
                    text = message.get("body", {}).get("text", "")

                    if not user_id or not text:
                        continue

                    if text.strip().lower() in [
                        "/start", "начать", "меню"
                    ]:
                        send_menu(user_id)
                    else:
                        send_menu(user_id)

                # Нажатие на кнопку
                elif update.get("update_type") == "message_callback":
                    callback = update.get("callback", {})
                    user = callback.get("user", {})
                    user_id = user.get("user_id")
                    payload = callback.get("payload", "")

                    if user_id and payload:
                        handle_button(user_id, payload)

        except Exception:
            logging.exception("Ошибка при получении сообщений")
            time.sleep(5)


if __name__ == "__main__":
    main()
