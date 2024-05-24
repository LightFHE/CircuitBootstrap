#ifndef _RLWE_CRYPTOPARAMETERS_H_
#define _RLWE_CRYPTOPARAMETERS_H_


#include "binfhe-constants.h"
#include "math/discretegaussiangenerator.h"
#include "lattice/lat-hal.h"

namespace lbcrypto {

class RLWECryptoParams {
public:
    RLWECryptoParams() = default;
    
    /**
   * Main constructor for RLWECryptoParams
   *
   * @param m cyclotomic ring order for RLWE used in bootstrapping
   * @param N ring dimension for RLWE used in bootstrapping 
   * @param Q modulus for RingGSW/RLWE used in bootstrapping
   * @param std standard deviation of noise
   * @param baseHT the base used for homotrace
   * @param digitsHT the digit length used for homotrace
   * @param baseSS the base used for scheme switching
   * @param digitsSS the digit length used for scheme switching
   * @param keyDist the key distribution
   * @param signEval flag if sign evaluation is needed
   */
    explicit RLWECryptoParams(uint32_t m, uint32_t N, const NativeInteger& Q,
                             double std, uint32_t baseHT, uint32_t digitsHT, uint32_t baseSS, 
                             uint32_t digitsSS, SecretKeyDist keyDist = UNIFORM_BINARY, bool signEval = false)
        : m_m(m),
          m_N(N),
          m_Q(Q),
          m_baseHT(baseHT), 
          m_digitsHT(digitsHT), 
          m_baseSS(baseSS), 
          m_digitsSS(digitsSS), 
          m_keyDist(keyDist),
          m_polyParams{std::make_shared<ILNativeParams>(m, Q)} {
        if (!m_m)
            OPENFHE_THROW(config_error, "m_m (cyclotomic ring order) can not be zero");
        if (!m_N)
            OPENFHE_THROW(config_error, "m_N (ring dimension) can not be zero");
        if (!m_Q)
            OPENFHE_THROW(config_error, "m_Q (modulus for RingGSW/RLWE) can not be zero");
        if (!baseHT)
            OPENFHE_THROW(config_error, "m_baseHT (the base used for hometrace) can not be zero");
        if (!digitsHT)
            OPENFHE_THROW(config_error, "m_digitsHT (the digits used for hometrace) can not be zero");
        if (!baseSS)
            OPENFHE_THROW(config_error, "m_baseSS (the base used for scheme switch) can not be zero");
        if (!digitsSS)
            OPENFHE_THROW(config_error, "m_digitsSS (the digits used for scheme switch) can not be zero");
        if (m_Q.GetMSB() > MAX_MODULUS_SIZE)
            OPENFHE_THROW(config_error, "Q.GetMSB() > MAX_MODULUS_SIZE");
        auto logQ{log(m_Q.ConvertToDouble())};
        m_EXdigitsHT = static_cast<uint32_t>(std::ceil(logQ / log(static_cast<double>(m_baseHT))));
        m_EXdigitsSS = static_cast<uint32_t>(std::ceil(logQ / log(static_cast<double>(m_baseSS))));
        m_dgg.SetStd(std);
        m_ht_dgg.SetStd(std);
        m_ss_dgg.SetStd(std);
        PreCompute(signEval); 
    }
    
    /**
   * Performs precomputations based on the supplied parameters
   */
    void PreCompute(bool signEval = false);

    uint32_t Getm() const {
        return m_m;
    }

    uint32_t GetN() const {
        return m_N;
    }

    const NativeInteger& GetQ() const {
        return m_Q;
    }

    uint32_t GetBaseHT() const {
        return m_baseHT;
    }

    uint32_t GetDigitsHTA() const {
        return m_digitsHT;
    }

    uint32_t GetDigitsHT() const {
        return m_EXdigitsHT;
    }

    uint32_t GetBaseSS() const {
        return m_baseSS;
    }
    
    uint32_t GetDigitsSSA() const {
        return m_digitsSS;
    }

    uint32_t GetDigitsSS() const {
        return m_EXdigitsSS;
    }

    const std::vector<NativeInteger>& GetHTPower() const {
        return m_HTpower;
    }

    const std::vector<NativeInteger>& GetSSPower() const {
        return m_SSpower;
    }

    const std::vector<NativeInteger>& GetAHTPower() const {
        return m_AHTpower;
    }

    const std::vector<NativeInteger>& GetASSPower() const {
        return m_ASSpower;
    }
    
    const DiscreteGaussianGeneratorImpl<NativeVector>& GetDgg() const {
        return m_dgg;
    }

    const DiscreteGaussianGeneratorImpl<NativeVector>& GetHTDgg() const {
        return m_ht_dgg;
    }

    const DiscreteGaussianGeneratorImpl<NativeVector>& GetSSDgg() const {
        return m_ss_dgg;
    }

    const std::shared_ptr<ILNativeParams> GetPolyParams() const {
        return m_polyParams;
    }

    const SecretKeyDist GetKeyDist() const {
        return m_keyDist;
    }
private:
    // cyclotomic ring order for RingGSW/RingLWE scheme
    uint32_t m_m{};
    // ring dimension for RingGSW/RingLWE scheme
    uint32_t m_N{};
    // modulus for the RingGSW/RingLWE scheme
    NativeInteger m_Q{};
    // Base used in homtrace
    uint32_t m_baseHT{};
    // Approximate digits used in homtrace
    uint32_t m_digitsHT{};
    // Exact digits in homtrace
    uint32_t m_EXdigitsHT{};
    // Base used in scheme switching
    uint32_t m_baseSS{};
    // Approximate digits used in scheme switching
    uint32_t m_digitsSS{};
    // Exact digits in scheme switching
    uint32_t m_EXdigitsSS{};

    // A vector of powers of baseHT
    std::vector<NativeInteger> m_HTpower;

    // A vector of base of HT approximate decomposition
    std::vector<NativeInteger> m_AHTpower;

    // A vector of powers of baseSS
    std::vector<NativeInteger> m_SSpower;

    // A vector of base of SS approximate decomposition
    std::vector<NativeInteger> m_ASSpower;

    // Secret key distribution: GAUSSIAN, UNIFORM_TERNARY, UNIFORM_BINARY,etc.
    SecretKeyDist m_keyDist{SecretKeyDist::UNIFORM_BINARY};
    // Error distribution generator
    DiscreteGaussianGeneratorImpl<NativeVector> m_dgg;
    // Error distribution generator for homtrace
    DiscreteGaussianGeneratorImpl<NativeVector> m_ht_dgg;
    // Error distribution generator for scheme switching
    DiscreteGaussianGeneratorImpl<NativeVector> m_ss_dgg;

    // Parameters for polynomials in RingLWE
    std::shared_ptr<ILNativeParams> m_polyParams;
};

}//namespace lbcrypto
#endif