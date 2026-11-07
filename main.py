import os
import time
import requests

TOKEN = os.getenv("MAX_TOKEN")
API_URL = "https://platform-api2.max.ru"

if not TOKEN:
    raise ValueError("Не указан токен MAX_TOKEN")

headers = {
    "Authorization": TOKEN,
    "Content-Type": "application/json"
}

def check_connection():
    response = requests.get(
        f"{API_URL}/me",
        headers=headers,
        timeout=15
    )
    response.raise_for_status()
    print("Бот подключён:", response.json())

def send_message(user_id, text):
    response = requests.post(
        f"{API_URL}/messages",
        headers=headers,
        params={"user_id": user_id},
        json={"text": text},
        timeout=15
    )
    response.raise_for_status()

def main():
    check_connection()
    print("Тестовая версия запущена")

if __name__ == "__main__":
    main()
