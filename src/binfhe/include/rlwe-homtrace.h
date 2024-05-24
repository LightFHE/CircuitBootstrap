#ifndef _RLWE_HOMTRACE_H_
#define _RLWE_HOMTRACE_H_

#include "rlwe-homtracekey.h"
#include "rlwe-cryptoparameters.h"
#include "rlwe-ciphertext.h"
namespace lbcrypto{

/**
 * @brief homomorphically evaluate the trace function described in
 * https://eprint.iacr.org/2020/015.pdf Algorithm 1
 */
class RingLWEHomTrace {
public:
    RingLWEHomTrace() = default;

    /**
   * Key generation for homtrace
   *
   * @param params a shared pointer to RingLWE scheme parameters
   * @param skNTT secret key polynomial in the EVALUATION representation
   * @return a shared pointer to the resulting keys
   */
    RLWEHomTraceKey KeyGenHT(const std::shared_ptr<RLWECryptoParams>& params, const NativePoly& skNTT) const;

    /**
   * Main homtrace function used in bootstrapping
   *
   * @param params a shared pointer to RingLWE scheme parameters
   * @param ek the homtrace key
   * @param ct input RingLWE ciphertext
   */
    void EvalHT(const std::shared_ptr<RLWECryptoParams>& params, ConstRLWEHomTraceKey& ek, RLWECiphertext& ct) const;

   /**
   * The signed digit decomposition which takes a ring element input and outputs a vector of its digits, i.e.,
   * decompose(a) = (a_0, ..., a_{d-1}) = R^d.
   *
   * @param params a shared pointer to RingLWE scheme parameters
   * @param input input ring element
   * @param output decomposed value
   */
    void SignedDigitDecompose(const std::shared_ptr<RLWECryptoParams>& params, const NativePoly& input,
                            std::vector<NativePoly>& output) const;

private:
    /**
   * Key generation for automorphism
   *
   * @param params a shared pointer to RingLWE scheme parameters
   * @param skNTT secret key polynomial in the EVALUATION representation
   * @param k the index of automorphism
   * @return a shared pointer to the resulting keys
   */
    RingGSWEvalKey KeyGenAuto(const std::shared_ptr<RLWECryptoParams>& params, const NativePoly& skNTT, uint32_t k) const;
   
   /**
   * Main homomorphic automorphism function used in field trace evaluation
   *
   * @param params a shared pointer to RingLWE scheme parameters
   * @param a index of automorphism
   * @param ak evaluation key of automorphism
   * @param ct input RingLWE ciphertext
   */
    void Automorphism(const std::shared_ptr<RLWECryptoParams>& params, const uint32_t& a,
                      ConstRingGSWEvalKey& ak, RLWECiphertext& ct) const;

};
}
#endif