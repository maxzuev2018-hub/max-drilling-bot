import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

TOKEN = os.getenv("MAX_TOKEN")
API_URL = "https://platform-api2.max.ru"

@app.route("/", methods=["GET"])
def home():
    return "MAX Drilling Bot is running!"

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(silent=True) or {}

    if data.get("update_type") == "message_created":
        message = data.get("message", {})
        sender = message.get("sender", {})
        user_id = sender.get("user_id")
        text = message.get("body", {}).get("text", "")

        if user_id and text:
            send_message(
                user_id,
                "Здравствуйте! Добро пожаловать! Это бот алмазного бурения."
            )

    return jsonify({"ok": True})

def send_message(user_id, text):
    if not TOKEN:
        raise ValueError("Не задан MAX_TOKEN")

    response = requests.post(
        f"{API_URL}/messages",
        headers={"Authorization": TOKEN},
        params={"user_id": user_id},
        json={"text": text},
        timeout=15
    )
    response.raise_for_status()
