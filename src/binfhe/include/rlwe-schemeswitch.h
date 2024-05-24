#ifndef _RLWE_SCHEMESWITCH_H
#define _RLWE_SCHEMESWITCH_H

#include "rlwe-cryptoparameters.h"
#include "rlwe-schemeswitchkey.h"
#include "rlwe-ciphertext.h"

namespace lbcrypto{

/**
 * @brief scheme switching algorithms described in
 * https://eprint.iacr.org/2023/112 section 3.1
 */
class RingLWESchemeSwitch {
public:
    RingLWESchemeSwitch() = default;

    /**
   * Key generation for scheme switch
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param skNTT secret key polynomial in the EVALUATION representation
   * @return a shared pointer to the resulting keys
   */
    RLWESchemeSwitchKey KeyGenSS(const std::shared_ptr<RLWECryptoParams>& params, const NativePoly& skNTT) const;

    /**
   * Main scheme switch function used in bootstrapping
   *
   * @param params a shared pointer to RingLWE scheme parameters
   * @param ek the scheme switch key
   * @param ct previous ciphertext
   */
    void EvalSS(const std::shared_ptr<RLWECryptoParams>& params, ConstRLWESchemeSwitchKey& ek,
                        RLWECiphertext& ct) const;

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
};
}
#endif