import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

TOKEN = os.getenv("MAX_TOKEN")
API_URL = "https://platform-api2.max.ru"

HEADERS = {
    "Authorization": TOKEN or "",
    "Content-Type": "application/json"
}

@app.route("/", methods=["GET"])
def home():
    return "MAX Drilling Bot is running!"

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.json

    if not data:
        return jsonify({"ok": True})

    update_type = data.get("update_type")

    if update_type == "message_created":
        message = data.get("message", {})
        sender = message.get("sender", {})
        recipient = message.get("recipient", {})

        user_id = sender.get("user_id")
        text = message.get("body", {}).get("text", "")

        if user_id and text:
            send_message(user_id, "Здравствуйте! Добро пожаловать! Это бот алмазного бурения.")

    return jsonify({"ok": True})

def send_message(user_id, text):
    response = requests.post(
        f"{API_URL}/messages",
        headers=HEADERS,
        params={"user_id": user_id},
        json={"text": text},
        timeout=15
    )

    response.raise_for_status()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
