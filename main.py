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
