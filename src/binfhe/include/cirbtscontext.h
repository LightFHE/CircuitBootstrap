#ifndef _CIRBTSCONTEXT_H
#define _CIRBTSCONTEXT_H

#include "cirbts-base-params.h"
#include "lwe-cryptoparameters.h"
#include "rlwe-cryptoparameters.h"
#include "rgsw-cryptoparameters.h"
#include "rlwe-ske.h"
#include "cirbts-base-scheme.h"

#include "lattice/stdlatticeparms.h"
#include "utils/serializable.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace lbcrypto{
/**
 * @brief CirBTSContextParams
 *
 * The parameters of circuitbootstrapping
 */
struct CirBTSContextParams{
    usint numberBits;
    usint cyclOrder;//the order of cyclotomic ring

    // for LWE crypto parameters
    usint latticeParam;//LWE dimension
    usint mod;  // modulus for additive LWE
    double stdDev; // standard deviation of noise
    // for Ring GSW + RLWE parameters
    usint BaseEP;  // gadget base used in the MV-FBS
    usint DigitsEP;  // gadget length used in the MV-FBS
    usint BaseHT;      //gadget base for the HomTrace
    usint DigitsHT; //gadget length for the Homtrace
    usint BaseSS; //gadget base for the scheme switching
    usint DigitsSS; //gadgt length for the scheme switching
    usint BaseCC; //gadget base for the circuit computation
    usint DigitsCC; //gadget length for the circuit computation
  
    SecretKeyDist keyDist0;// key distribution in level 0
    SecretKeyDist keyDist2;// key distribution in level 2  
};
/**
 * @brief CirBTSContext
 *
 * The wrapper class for circuitbootstrap FHE
 */
class CirBTSContext {
public:
    CirBTSContext() = default;

    /**
   * Creates a crypto context using predefined parameters sets. Recommended for
   * most users.
   *
   * @param set the parameter set: STD128_CircuitBootstrap_AUTO, STD128_CircuitBootstrap_CMUX with their variants, see binfhe_constants.h
   * @param method the bootstrapping method (CircuitBootstrap_AUTO or CircuitBootstrap_CMUX)
   * @return create the cryptocontext
   */
    void GenerateCirBTSContext(CirBTS_PARAMSET set, BINFHE_METHOD method = GINX);

    /**
   * Gets the circuit bootstrapping key.
   *
   * @return a shared pointer to the circuit bootstrapping key
   */
    const RingGSWCirBTKey& GetCirBTSKey() const {
        return m_BTKey;
    }

    /**
   * Gets the refresh key.
   *
   * @return a shared pointer to the refresh key
   */
    const RingGSWACCKey& GetRefreshKey() const {
        return m_BTKey.RFkey;
    }

    /**
   * Gets the homtrace key.
   *
   * @return a shared pointer to the homtrace key
   */
    const RLWEHomTraceKey& GetHomTraceKey() const {
        return m_BTKey.HTkey;
    }

    /**
   * Gets the scheme switch key.
   *
   * @return a shared pointer to the scheme switch key
   */
    const RLWESchemeSwitchKey& GetSchemeSwitchingKey() const {
        return m_BTKey.SSkey;
    }

    /**
   * Generates a secret key for the main LWE scheme
   *
   * @return a shared pointer to the secret key
   */
    LWEPrivateKey KeyGen() const;

    /**
    * Generate level 2 secret
   */
    RLWEPrivateKey RLWEKeyGen() const;

    /**
   * Encrypts a bit or integer using a secret key (symmetric key encryption)
   *
   * @param sk the secret key
   * @param m the plaintext
   * @param p plaintext modulus
   * @return a shared pointer to the ciphertext
   */
    LWECiphertext Encrypt(ConstLWEPrivateKey& sk, LWEPlaintext m, LWEPlaintextModulus p = 2) const;

    /**
   * Decrypts a ciphertext using a secret key
   *
   * @param sk the secret key
   * @param ct the ciphertext
   * @param result plaintext result
   * @param p plaintext modulus
   */
    void Decrypt(ConstLWEPrivateKey& sk, ConstLWECiphertext& ct, LWEPlaintext* result, LWEPlaintextModulus p = 2) const;

    /**
   * Generates circuit boostrapping keys
   *
   * @param sk LWE secret key(level 0)
   * @param skNTT RLWE secret key(level 2)
   * @param keygenMode key generation mode for symmetric or public encryption
   */
    void CirBTKeyGen(ConstLWEPrivateKey& sk, ConstRLWEPrivateKey skNTT, KEYGEN_MODE keygenMode = SYM_ENCRYPT);

    /**
   * Clear the bootstrapping keys in the current context
   */
    void ClearBTKeys() {
        m_BTKey.RFkey.reset();
        m_BTKey.HTkey.reset();
        m_BTKey.SSkey.reset();
    }

    /**
    * Bootstap a LWE ciphertext to RGSW ciphertext
    * 
    * @param ct a shared pointer of  LWE ciphertext to be circuit bootstrapping 
    */
    RGSWCiphertext CircuitBootstrapping(ConstLWECiphertext& ct) const;

    /**
   * Getter for params
   * @return
   */
    const std::shared_ptr<CirBTSCryptoParams>& GetParams() {
        return m_params;
    }

    /**
   * Getter for LWE scheme
   * @return
   */
    const std::shared_ptr<LWEEncryptionScheme>& GetLWEScheme() {
        return m_LWEscheme;
    }

    /**
   * Getter for CirBTS scheme params
   * @return
   */
    const std::shared_ptr<CirBTSScheme>& GetCirBTSScheme() {
        return m_cirbtsscheme;
    }

    /**
   * Precompute LUT
   */
    void PreCompute();

private:
    //Shared pointer to circuit bootstrapping parameters
    std::shared_ptr<CirBTSCryptoParams> m_params{nullptr};

    //shared pointer to the underlying additive LWE scheme
    std::shared_ptr<LWEEncryptionScheme> m_LWEscheme{nullptr};

    //shared pointer to the underlying RLWE scheme
    std::shared_ptr<RLWEEncryptionScheme> m_RLWEscheme{nullptr};

    //shared pointer to the underlying circuit bootstrapping scheme
    std::shared_ptr<CirBTSScheme> m_cirbtsscheme{nullptr};

    //Struct contating the bootstrapping keys
    RingGSWCirBTKey m_BTKey = {0};

};

}//namespace lbcryto;
#endif