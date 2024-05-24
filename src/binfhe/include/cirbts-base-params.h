#ifndef _CIRBTS_BASE_PARAMS_H_
#define _CIRBTS_BASE_PARAMS_H_

#include "utils/serializable.h"

#include "lwe-cryptoparameters.h"
#include "rlwe-cryptoparameters.h"
#include "rgsw-cryptoparameters.h"

namespace lbcrypto{

/**
 * @brief Class that stores all parameters for the RingGSW scheme used in circuit
 * bootstrapping
 */
class CirBTSCryptoParams {
public:
    CirBTSCryptoParams() = default;
        /**
   * Main constructor for CirBTSCryptoParams
   *
   * @param lweparams a shared poiter to an instance of LWECryptoParams
   * @param rgswparams1 a shared poiter to an instance of RingGSWCryptoParams
   * @param rlweparams a shared poiter to an instance of RingLWECryptoParams
   * @param rgswparams2 a shared poiter to an instance of RingGSWCryptoParams
   */
    CirBTSCryptoParams(const std::shared_ptr<LWECryptoParams>& lweparams,
                       const std::shared_ptr<RingGSWCryptoParams>& rgswparams1,
                       const std::shared_ptr<RLWECryptoParams>& rlweparams,
                       const std::shared_ptr<RingGSWCryptoParams>& rgswparams2)
        : m_LWEParams(lweparams), m_RGSWParams1(rgswparams1), m_RLWEParams(rlweparams), m_RGSWParams2(rgswparams2){
            PreCompute();
        }

    void PreCompute();
    /**
   * Getter for LWE params
   * @return
   */
    const std::shared_ptr<LWECryptoParams>& GetLWEParams() const {
        return m_LWEParams;
    }

    /**
   * Getter for RingGSW params
   * @return
   */
    const std::shared_ptr<RingGSWCryptoParams>& GetRingGSWParams1() const {
        return m_RGSWParams1;
    }

   /**
   * Getter for RingLWE params
   * @return
   */
    const std::shared_ptr<RLWECryptoParams>& GetRLWEParams() const {
        return m_RLWEParams;
    }

    /**
   * Getter for RingGSW params
   * @return
   */
    const std::shared_ptr<RingGSWCryptoParams>& GetRingGSWParams2() const {
        return m_RGSWParams2;
    }

    /**
   * Getter for digitsEP
   * @return
   */
    const uint32_t GetDigitsEP() const {
        return m_RGSWParams1->GetDigitsGA();
    }

    /**
   * Getter for digitsCC
   * @return
   */
    const uint32_t GetDigitsCC() const {
        return m_RGSWParams2->GetDigitsGA();
    }

    /**
   * Getter for LUT
   * @return
   */
    const NativePoly& GetLUT() const {
        return m_LUT;
    }

    const NativePoly& GetMonomial(uint32_t i) const{
        return m_monomials[i];
    }

private:
    // shared pointer to an instance of LWECryptoParams
    std::shared_ptr<LWECryptoParams> m_LWEParams{nullptr};

    // shared pointer to an instance of RGSWCryptoParams1
    std::shared_ptr<RingGSWCryptoParams> m_RGSWParams1{nullptr};

    // shared pointer to an instance of RLWECryptoParams
    std::shared_ptr<RLWECryptoParams> m_RLWEParams{nullptr};

    // shared pointer to an instance of RGSWCryptoParams2
    std::shared_ptr<RingGSWCryptoParams> m_RGSWParams2{nullptr};
 
    //The LUT
    NativePoly m_LUT;

    // Precomputed polynomials in Format::EVALUATION representation for X^{-i}
    // (used only for CGGI bootstrapping)
    std::vector<NativePoly> m_monomials;

};

}//namespace lbcrypto
#endif