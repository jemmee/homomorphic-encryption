// brew install seal cmake
//
// mkdir build && cd build
// cmake -DCMAKE_C_COMPILER=/usr/bin/clang \
      -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
      -DCMAKE_PREFIX_PATH=/opt/homebrew ..
// make
// ./seal_test

#include "seal/seal.h"
#include <iostream>

using namespace std;
using namespace seal;

int main() {
  // 1. Setup Encryption Parameters
  EncryptionParameters parms(scheme_type::bfv);
  size_t poly_modulus_degree = 4096;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
  // parms.set_plain_modulus(1024);

  // 2. To a prime that supports batching:
  parms.set_plain_modulus(PlainModulus::Batching(4096, 20));
  // This helper function automatically finds a ~20-bit prime that works with
  // degree 4096.

  SEALContext context(parms);

  // 2. Generate Keys
  KeyGenerator keygen(context);
  SecretKey secret_key = keygen.secret_key();
  PublicKey public_key;
  keygen.create_public_key(public_key);

  // 3. Create Tools
  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);
  Decryptor decryptor(context, secret_key);
  BatchEncoder encoder(context);

  // 4. Encrypt 10 + 5
  Plaintext p1("A"), p2("5"); // Hexadecimal representation
  Ciphertext c1, c2, c_sum;

  encryptor.encrypt(p1, c1);
  encryptor.encrypt(p2, c2);

  // 5. Homomorphic Addition
  evaluator.add(c1, c2, c_sum);

  // 6. Decrypt
  Plaintext p_result;
  decryptor.decrypt(c_sum, p_result);

  cout << "Result of 10 + 5 (in hex): " << p_result.to_string() << endl;

  return 0;
}