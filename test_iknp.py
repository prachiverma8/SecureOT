from iknp import iknp_ot_extension

message_pairs = [
    ("Apple", "Mango"),
    ("Red", "Blue"),
    ("Python", "Java"),
    ("Delhi", "Mumbai"),
    ("Morning", "Night")
]

receiver_choices = [0, 1, 0, 1, 1]

result = iknp_ot_extension(
    message_pairs,
    receiver_choices
)

print("\n========== IKNP OT EXTENSION TEST ==========")

print("Number of base OTs:", result["base_ots"])
print("Number of extended OTs:", result["number_of_transfers"])

print("\nReceiver's choices and received messages:")

for i, message in enumerate(result["received_messages"]):
    print(
        f"Transfer {i + 1}: "
        f"Choice={receiver_choices[i]}, "
        f"Received={message}"
    )

print("\nExecution time:", result["execution_time_ms"], "ms")

print("\n========== TEST COMPLETED ==========")