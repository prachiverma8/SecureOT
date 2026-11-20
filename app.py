from performance import run_performance_test
from iknp import iknp_ot_extension
from flask import Flask, render_template, request

from ot_protocol import (
    create_sender_offer,
    create_receiver_request,
    encrypt_messages,
    decrypt_selected_message
)

app = Flask(__name__)

pending_transfer = {
    "message0": "",
    "message1": "",
    "private_key": None,
    "public_key": None
}


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/sender", methods=["GET", "POST"])
def sender():

    status = None

    if request.method == "POST":

        message0 = request.form.get("message0", "").strip()
        message1 = request.form.get("message1", "").strip()

        if message0 and message1:

            private_key, public_key = create_sender_offer()

            pending_transfer["message0"] = message0
            pending_transfer["message1"] = message1
            pending_transfer["private_key"] = private_key
            pending_transfer["public_key"] = public_key

            status = "Messages prepared. DH public key generated successfully!"

        else:
            status = "Please enter both messages."

    return render_template("sender.html", status=status)


@app.route("/receiver", methods=["GET", "POST"])
def receiver():

    received_message = None
    choice = None
    error = None

    if request.method == "POST":

        choice = request.form.get("choice")

        if pending_transfer["private_key"] is None:
            error = "No active transfer. Prepare messages in the Sender Dashboard first."

        elif choice not in ["0", "1"]:
            error = "Please select a valid message."

        else:
            try:
                choice_bit = int(choice)

                # Receiver creates its DH response
                receiver_private, receiver_public = create_receiver_request(
                    pending_transfer["public_key"],
                    choice_bit
                )

                # Sender encrypts both messages using derived keys
                encrypted_data = encrypt_messages(
                    pending_transfer["private_key"],
                    pending_transfer["public_key"],
                    receiver_public,
                    pending_transfer["message0"],
                    pending_transfer["message1"]
                )

                # Receiver decrypts only the selected ciphertext
                received_message = decrypt_selected_message(
                    receiver_private,
                    pending_transfer["public_key"],
                    choice_bit,
                    encrypted_data
                )

            except Exception as e:
                error = f"OT transfer failed: {str(e)}"

    return render_template(
        "receiver.html",
        received_message=received_message,
        choice=choice,
        error=error
    )


@app.route("/visualization")
def visualization():
    return render_template("visualization.html")
@app.route("/iknp", methods=["GET", "POST"])
def iknp():
    result = None
    error = None

    if request.method == "POST":
        try:
            message0 = request.form.getlist("message0")
            message1 = request.form.getlist("message1")
            choices = request.form.getlist("choice")

            message_pairs = list(zip(message0, message1))
            receiver_choices = [int(choice) for choice in choices]

            result = iknp_ot_extension(
                message_pairs,
                receiver_choices
            )

        except Exception as e:
            error = str(e)

    return render_template(
        "iknp.html",
        result=result,
        error=error
    )


@app.route("/performance")
def performance():

    results = None
    error = None

    try:
        results = run_performance_test()

    except Exception as e:
        error = str(e)

    return render_template(
        "performance.html",
        results=results,
        error=error
    )


if __name__ == "__main__":
    app.run(debug=True)