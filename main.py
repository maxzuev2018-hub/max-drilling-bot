import os
import time
import logging
import requests
import certifi
os.environ["REQUESTS_CA_BUNDLE"] = certifi.where()
logging.basicConfig(level=logging.INFO)

TOKEN = os.getenv("MAX_TOKEN")

if not TOKEN:
    raise RuntimeError("Не задан MAX_TOKEN в переменных Bothost")

API_URL = "https://platform-api2.max.ru"
HEADERS = {"Authorization": TOKEN}

def send_message(user_id, text):
    response = requests.post(
        f"{API_URL}/messages",
        headers=HEADERS,
        params={"user_id": user_id},
        json={"text": text},
        timeout=20
    )
    logging.info("Ответ MAX: %s %s", response.status_code, response.text)

def main():
    marker = None
    logging.info("Бот запущен и ожидает сообщения")

    while True:
        try:
            params = {"timeout": 30}
            if marker is not None:
                params["marker"] = marker

            response = requests.get(
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
