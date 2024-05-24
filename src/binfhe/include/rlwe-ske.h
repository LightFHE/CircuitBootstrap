//rlwe symmetric encryption
#ifndef RLWE_SKE_H
#define RLWE_SKE_H

#include "rlwe-privatekey.h"
#include "math/math-hal.h"
#include "rlwe-ciphertext.h"
#include "rlwe-cryptoparameters.h"

namespace lbcrypto{

/**
 * @brief symmetric RLWE encryption scheme
 */
class RLWEEncryptionScheme {
public:
    RLWEEncryptionScheme() = default;
    
    /**
   * Generates a secret key (binary secret) of dimension n using modulus q
   *
   * @param dimen  the dimension of RLWE scheme
   * @param modulus the modulus for the secret key
   * @return a shared pointer to the secret key
   */
    RLWEPrivateKey KeyGenBinary(usint dimen, const NativeInteger& modulus) const;

    /**
   * Generates a secret key (ternary secret) of dimension n using modulus q
   *
   * @param dimen  the dimension of RLWE scheme
   * @param modulus the modulus for the secret key
   * @return a shared pointer to the secret key
   */
    RLWEPrivateKey KeyGenTernary(usint dimen, const NativeInteger& modulus) const;

    /**
   * Generates a secret key (discrete Gaussian secret) of dimension n using modulus q
   *
   * @param dimen  the dimension of RLWE scheme
   * @param modulus the modulus for the secret key
   * @param std the standard deviation for the secret key
   * @return a shared pointer to the secret key
   */
    RLWEPrivateKey KeyGenGaussian(usint dimen, const NativeInteger& modulus, double std) const;

    /**
   * classical RLWE encryption
   * a is a randomly uniform polynomial of dimension n; with integers mod q
   * b = a*s + e + m floor(q/p) is an polynomial mod q
   *
   * @param params  a shared pointer to RLWE scheme parameters
   * @param sk the secret key
   * @param m the plaintext polynomial of message
   * @param p the plaintext modulus
   * @param mod the ciphertext modulus
   * @return a shared pointer to the RLWECiphertext
   */
    RLWECiphertext Encrypt(const std::shared_ptr<RLWECryptoParams>& params, ConstRLWEPrivateKey& sk,
                            NativePoly m, LWEPlaintextModulus p, NativeInteger mod) const;

    
    /**
   * RLWE decryption
   * m_result = Round(p/q*(b-a*s))
   *
   * @param params  a shared pointer to RLWE scheme parameters
   * @param sk the secret key
   * @param m the plaintext polynomial of message
   * @param p the plaintext modulus
   * @param mod the ciphertext modulus
   * @return a shared pointer to the RLWECiphertext
   */
    void Decrypt(const std::shared_ptr<RLWECryptoParams>& params, ConstRLWEPrivateKey& sk,
                    ConstRLWECiphertext& ct, NativePoly* result, LWEPlaintextModulus p) const;


    /**
   * The signed digit decomposition which takes a RLWE ciphertext input and outputs a vector of its digits, i.e.,
   * decompose((a,b)) = (a_0,b_0,..., a_{d-1},b_{d-1}) = R^(2d).
   *
   * @param params a shared pointer to RingLWE scheme parameters
   * @param input input rlwe ciphertext
   * @param base the base of gadget decomposition
   * @param digits the digits of approximate decomposition
   * @param output decomposed value
   */
    void SignedDigitDecompose(const std::shared_ptr<RLWECryptoParams>& params, ConstRLWECiphertext& input,
                              const uint32_t base, const uint32_t digits, std::vector<NativePoly>& output) const;

};
}
#endif