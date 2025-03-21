import json

# Load both proof files
with open("proof1.json", "r") as f:
    orig_proof = json.load(f)

with open("proof.json", "r") as f:
    new_proof = json.load(f)

# Compare both proofs
if orig_proof == new_proof:
    print("✅ The proofs are identical! The process is deterministic.")
else:
    print("⚠️ The proofs are different! Something changed in the model, data, or settings.")


# Compare keys and structure
print("Original Proof Keys:", orig_proof.keys())
print("New Proof Keys:", new_proof.keys())

if orig_proof.keys() != new_proof.keys():
    print("⚠️ The proof structures are different!")
else:
    print("✅ The proof structures match.")


ignored_keys = ["timestamp"]

for key in orig_proof.keys():
    if key in ignored_keys:
        continue
    if orig_proof[key] != new_proof[key]:
        print(f"❌ Difference found in key: {key}")


# with open("input.json", "r") as f:
#     current_input = json.load(f)

# with open("OrigInput.json", "r") as f:  # If you stored original inputs
#     original_input = json.load(f)

# if current_input != original_input:
#     print("⚠️ The inputs are different! This affects proof generation.")
# else:
#     print("✅ Inputs are identical.")
        