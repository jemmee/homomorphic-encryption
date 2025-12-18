# python3 -m pip install phe
#
# python3 secure_tally_test.py

from phe import paillier

# 1. Key Generation (Local/Secure)
# Generating a 2048-bit keypair for strong security
print("Generating Paillier keypair...")
public_key, private_key = paillier.generate_paillier_keypair()

# 2. Encryption (Individual Users)
# Let's say we have three separate users with secret data
user_data = [123.45, 67.89, 10.00]

print(f"Encrypting original values: {user_data}")
encrypted_values = [public_key.encrypt(x) for x in user_data]

# 3. Homomorphic Addition (Untrusted Server)
# The server receives these 'encrypted_values' (which are giant integers)
# It can add them together using standard '+' syntax
print("\nServer is performing homomorphic addition...")
encrypted_sum = sum(encrypted_values)

# The server can also perform scalar multiplication (e.g., adding a 10% tax/bonus)
# E(m) * 1.1 = E(m * 1.1)
encrypted_sum_with_bonus = encrypted_sum * 1.1

# 4. Decryption (Local/Secure)
# Only the holder of the private_key can see the result
result = private_key.decrypt(encrypted_sum)
result_with_bonus = private_key.decrypt(encrypted_sum_with_bonus)

print("\n--- Results ---")
print(f"Decrypted Sum: {result:.2f}")
print(f"Decrypted Sum (with 10% bonus): {result_with_bonus:.2f}")
print(f"Mathematical Check: {sum(user_data) * 1.1:.2f}")
