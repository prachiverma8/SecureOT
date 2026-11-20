import os
import time
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt

from ot_protocol import (
    create_sender_offer,
    create_receiver_request,
    encrypt_messages,
    decrypt_selected_message
)

from iknp import iknp_ot_extension


def benchmark_basic_ot(message_pairs, choices):

    start = time.perf_counter()

    received_messages = []

    for (message0, message1), choice in zip(message_pairs, choices):

        private_key, public_key = create_sender_offer()

        receiver_private, receiver_public = create_receiver_request(
            public_key, choice
        )

        encrypted_data = encrypt_messages(
            private_key,
            public_key,
            receiver_public,
            message0,
            message1
        )

        received_message = decrypt_selected_message(
            receiver_private,
            public_key,
            choice,
            encrypted_data
        )

        received_messages.append(received_message)

    elapsed = (time.perf_counter() - start) * 1000

    return round(elapsed, 3), received_messages


def run_performance_test():

    transfer_sizes = [1, 5, 10, 25, 50, 100]

    basic_times = []
    iknp_times = []
    base_ot_times = []
    extension_times = []

    for size in transfer_sizes:

        message_pairs = [
            (f"Message_A_{i}", f"Message_B_{i}")
            for i in range(size)
        ]

        choices = [i % 2 for i in range(size)]

        # Basic OT benchmark
        basic_time, basic_received = benchmark_basic_ot(
            message_pairs, choices
        )

        basic_times.append(basic_time)

        # IKNP benchmark
        iknp_result = iknp_ot_extension(
            message_pairs, choices
        )

        iknp_times.append(
            iknp_result["execution_time_ms"]
        )

        base_ot_times.append(
            iknp_result["base_ot_time_ms"]
        )

        extension_times.append(
            iknp_result["extension_time_ms"]
        )

        # Verify correctness
        expected_messages = [
            pair[choice]
            for pair, choice in zip(message_pairs, choices)
        ]

        if basic_received != expected_messages:
            raise RuntimeError("Basic OT verification failed.")

        if iknp_result["received_messages"] != expected_messages:
            raise RuntimeError("IKNP verification failed.")

    # Generate performance graph
    graph_directory = os.path.join(
        "static", "graphs"
    )

    os.makedirs(graph_directory, exist_ok=True)

    graph_path = os.path.join(
        graph_directory, "performance_comparison.png"
    )

    plt.figure(figsize=(11, 5.5), facecolor="#111c30")

    ax = plt.gca()
    ax.set_facecolor("#162238")

    plt.plot(
        transfer_sizes,
        basic_times,
        marker="o",
        linewidth=2.5,
        markersize=7,
        label="Basic OT"
    )

    plt.plot(
        transfer_sizes,
        base_ot_times,
        marker="s",
        linewidth=2.5,
        markersize=7,
        label="Base OT Setup"
    )

    plt.plot(
        transfer_sizes,
        extension_times,
        marker="^",
        linewidth=2.5,
        markersize=7,
        label="OT Extension"
    )

    plt.yscale("log")

    plt.xlabel(
        "Number of OT Transfers",
        color="#dbeafe",
        fontsize=11
    )

    plt.ylabel(
        "Execution Time (ms, logarithmic scale)",
        color="#dbeafe",
        fontsize=11
    )

    plt.title(
        "Basic OT vs IKNP Setup and Extension Time",
        color="#60a5fa",
        fontsize=14,
        pad=18
    )

    plt.xticks(transfer_sizes, color="#dbeafe")
    plt.yticks(color="#dbeafe")

    ax.tick_params(axis="both", colors="#dbeafe")

    for spine in ax.spines.values():
        spine.set_color("#36547e")

    plt.grid(True, alpha=0.2, which="both")

    plt.legend(
        facecolor="#203552",
        edgecolor="#36547e",
        labelcolor="#dbeafe"
    )

    plt.tight_layout()

    plt.savefig(
        graph_path,
        dpi=180,
        facecolor="#111c30",
        bbox_inches="tight"
    )

    plt.close()

    # Prepare experimental results
    results = []

    for i, size in enumerate(transfer_sizes):

        results.append({
            "transfers": size,
            "basic_time": basic_times[i],
            "iknp_time": iknp_times[i],
            "base_ot_time": base_ot_times[i],
            "extension_time": extension_times[i]
        })

    return {
        "results": results,
        "base_ots": 128,
        "graph": "graphs/performance_comparison.png"
    }