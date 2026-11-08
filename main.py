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

# Проверенный сертификат MAX
CA_FILE = Path(__file__).resolve().parent / "russian_trusted_sub_ca_2024.pem"

EXPECTED_SHA256 = (
    "2155785036c900dbb5f1bb2a1569c80c"
    "55595bd6bf94867a29bbddbc7d88a3f2"
)

if not CA_FILE.exists():
    raise FileNotFoundError(f"Не найден сертификат: {CA_FILE}")

# Проверяем подлинность сертификата
pem_data = CA_FILE.read_text(encoding="ascii")
der_data = ssl.PEM_cert_to_DER_cert(pem_data)
actual_hash = hashlib.sha256(der_data).hexdigest()

if actual_hash != EXPECTED_SHA256:
    raise RuntimeError("Отпечаток сертификата не совпадает!")

# Создаём SSL-контекст только для MAX
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

def send_message(user_id, text):
    response = session.post(
        f"{API_URL}/messages",
        headers=HEADERS,
        params={"user_id": user_id},
        json={"text": text},
        timeout=20
    )
    logging.info(
        "Ответ MAX: %s %s",
        response.status_code,
        response.text
    )

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
                if update.get("update_type") != "message_created":
                    continue

                message = update.get("message", {})
                sender = message.get("sender", {})
                user_id = sender.get("user_id")
                text = message.get("body", {}).get("text", "")

                if not user_id or not text:
                    continue

                answer = (
                    "Здравствуйте! 👋\n"
                    "Вы обратились в службу алмазного бурения.\n\n"
                    "Выполняем бурение отверстий в Санкт-Петербурге "
                    "и Ленинградской области.\n\n"
                    "Напишите, какое отверстие вам нужно."
                )

                send_message(user_id, answer)

        except Exception:
            logging.exception("Ошибка при получении сообщений")
            time.sleep(5)

if __name__ == "__main__":
    main()
