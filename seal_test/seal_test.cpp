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

// A simple Base64 encoder for the serialized binary data
string base64_encode(const string &in) {
  string out;
  int val = 0, valb = -6;
  static const string b64_chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (unsigned char c : in) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(b64_chars[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6)
    out.push_back(b64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
  while (out.size() % 4)
    out.push_back('=');
  return out;
}

// 2. THE FIX: The Overloaded Function
// This version takes a Ciphertext and handles the serialization for you.
string base64_encode(const Ciphertext &ct) {
  stringstream ss;
  ct.save(ss);                    // Serialize the object into binary bytes
  return base64_encode(ss.str()); // Convert bytes to string and encode
}

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

  cout << "c1: " << base64_encode(c1) << endl;
  cout << "c2: " << base64_encode(c2) << endl;

  // 5. Homomorphic Addition
  evaluator.add(c1, c2, c_sum);

  cout << "c_sum: " << base64_encode(c_sum) << endl;

  // 6. Decrypt
  Plaintext p_result;
  decryptor.decrypt(c_sum, p_result);

  cout << "Result of 10 + 5 (in hex): " << p_result.to_string() << endl;

  return 0;
}