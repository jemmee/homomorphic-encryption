# brew install gcc
# export CC=/opt/homebrew/bin/gcc-15
# export CXX=/opt/homebrew/bin/g++-15
#
# pip install Pyfhel
#
# python3 bfv_test.py

import numpy as np
from Pyfhel import Pyfhel

# 1. Initialize Pyfhel and generate keys
HE = Pyfhel()
# n is the degree of polynomial (affects security and speed)
# t is the plaintext modulus
HE.contextGen(scheme='bfv', n=2**14, t_bits=20) 
HE.keyGen()

# 2. Encrypt two integers
# Pyfhel works with NumPy arrays for batching
integer1 = np.array([10], dtype=np.int64)
integer2 = np.array([5], dtype=np.int64)

ctxt1 = HE.encryptInt(integer1)
ctxt2 = HE.encryptInt(integer2)

# 3. Perform FHE Operations
# Addition: 10 + 5 = 15
ctxt_sum = ctxt1 + ctxt2

# Multiplication: 10 * 5 = 50
# Note: In FHE, multiplication increases 'noise' significantly
ctxt_prod = ctxt1 * ctxt2

# 4. Decrypt the results
res_sum = HE.decryptInt(ctxt_sum)
res_prod = HE.decryptInt(ctxt_prod)

print(f"Encrypted Sum (10+5): {res_sum[0]}")
print(f"Encrypted Product (10*5): {res_prod[0]}")