#ifndef _RGSW_ACC_CGGI2_H_
#define _RGSW_ACC_CGGI2_H_

#include "rgsw-acc.h"

#include <string>

namespace lbcrypto {
/**
 * @brief Ring GSW accumulator schemes described in
 * https://eprint.iacr.org/2018/421.pdf and https://eprint.iacr.org/2020/086
 */
class RingGSWAccumulatorCGGI2 final : public RingGSWAccumulator {
public:
    RingGSWAccumulatorCGGI2() = default;

    /**
   * Key generation for internal Ring GSW as described in https://eprint.iacr.org/2018/421.pdf
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param skNTT secret key polynomial in the EVALUATION representation
   * @param LWEsk the secret key
   * @return a shared pointer to the resulting keys
   */
    RingGSWACCKey KeyGenAcc(const std::shared_ptr<RingGSWCryptoParams>& params, const NativePoly& skNTT,
                            ConstLWEPrivateKey& LWEsk) const override;

    /**
   * Main accumulator function used in bootstrapping - GINX variant
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param ek the accumulator key
   * @param acc previous value of the accumulator
   * @param a value to update the accumulator with
   */
    void EvalAcc(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWACCKey& ek, RLWECiphertext& acc,
                 const NativeVector& a) const override;

private:
    /**
   * Key generation for internal Ring GSW as described in https://eprint.iacr.org/2020/086
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param skNTT secret key polynomial in the EVALUATION representation
   * @param m a plaintext
   * @return a shared pointer to the resulting keys
   */
    RingGSWEvalKey KeyGenCGGI(const std::shared_ptr<RingGSWCryptoParams>& params, const NativePoly& skNTT,
                              LWEPlaintext m) const;

    /**
   * CGGI Accumulation as described in https://eprint.iacr.org/2020/086
   * with ternary MUX introduced in paper https://eprint.iacr.org/2022/074.pdf section 5
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param ek evaluation keys for Ring GSW
   * @param a a value to add to the accumulator
   * @param acc previous value of the accumulator
   */
    void AddToAccCGGI(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWEvalKey& ek,
                     const NativeInteger& a, RLWECiphertext& acc) const;

    /**
   * The signed digit decomposition which takes an RLWE ciphertext input and outputs a vector of its digits, i.e., an
   * RLWE' ciphertext
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param input input RLWE ciphertext
   * @param output output RLWE' ciphertext
   */
    void SignedDigitDecompose2(const std::shared_ptr<RingGSWCryptoParams>& params, const std::vector<NativePoly>& input,
                              std::vector<NativePoly>& output) const;
};

};  // namespace lbcrypto

#endif
