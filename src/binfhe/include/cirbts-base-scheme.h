#ifndef _CIRBTS_BASE_SCHEME_H
#define _CIRBTS_BASE_SCHEME_H

#include "cirbts-base-params.h"
#include "lwe-pke.h"
#include "rlwe-ciphertext.h"
#include "rgsw-ciphertext.h"
#include "rgsw-acckey.h"
#include "rlwe-homtracekey.h"
#include "rlwe-schemeswitchkey.h"
#include "rgsw-acc.h"
#include "rgsw-acc-cggi.h"
#include "rgsw-acc-lmkcdey.h"
#include "rlwe-homtrace.h"
#include "rlwe-schemeswitch.h"
#include "rlwe-privatekey.h"
#include "rgsw-acc-cggi-binary.h"

#include <map>
#include <memory>
#include <vector>

namespace lbcrypto {

// The struct for storing bootstrapping keys
typedef struct {
    //refreshing key
    RingGSWACCKey RFkey;
    //Homtrace key
    RLWEHomTraceKey HTkey;
    //Scheme switching key
    RLWESchemeSwitchKey SSkey;
} RingGSWCirBTKey;

/**
 * @brief circuit bootstrapping schemes described in
 * https://eprint.iacr.org/2024/323
 */
class CirBTSScheme {
public:
    CirBTSScheme() = default;

    explicit CirBTSScheme(BINFHE_METHOD method) {
        if (method == GINX)
            ACCscheme = std::make_shared<RingGSWAccumulatorCGGI2>();
        else if (method == LMKCDEY)
            ACCscheme = std::make_shared<RingGSWAccumulatorLMKCDEY>();

        else
            OPENFHE_THROW(config_error, "method is invalid");
    }

    /**
   * Generates a refresh key
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param LWEsk a shared pointer to the secret key of LWE
   * @param skNTT a shared pointer to the secret key of the RLWE
   * @param keygenMode enum to indicate generation of secret key only (SYM_ENCRYPT) or
   * secret key, public key pair (PUB_ENCRYPT)
   * @return a shared pointer to the refresh key
   */
    RingGSWCirBTKey KeyGen(const std::shared_ptr<CirBTSCryptoParams>& params, ConstLWEPrivateKey& LWEsk, ConstRLWEPrivateKey skNTT,
                        KEYGEN_MODE keygenMode) const;


    /**
   * circuit bootstrapping
   */
    RGSWCiphertext CircuitBootstrap(const std::shared_ptr<CirBTSCryptoParams>& params, const RingGSWCirBTKey& ek,
                                    ConstLWECiphertext& ct) const;


     /**
   * Bootstrapping manyLUTs operation
   *
   * @param params a shared pointer to circuit bootstrapping scheme parameters
   * @param ek a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param LUT function to evaluate in the multi-value functional bootstrapping
   * @param bitwidth the bits represented numLUT in MV-FBS
   * @return a shared pointer to the resulting ciphertext
   */
    RLWECiphertext BootstrapManyLUT(const std::shared_ptr<CirBTSCryptoParams>& params, ConstRingGSWACCKey& ek,
                                    ConstLWECiphertext& ct, const NativePoly& LUT, uint32_t bitwidth) const;

     /**
   * Special modulus switching operation in MV-FBS
   *
   * @param v old value
   * @param q new modulus
   * @param Q old modulus
   * @param bitwidth the bits represented numLUT in MV-FBS
   * @return the value of modulus switching
   */
    NativeInteger SpecilMS(const NativeInteger& v, const NativeInteger& q, const NativeInteger& Q, const uint32_t bitwidth) const;

protected:
    std::shared_ptr<LWEEncryptionScheme> LWEscheme{std::make_shared<LWEEncryptionScheme>()};
    std::shared_ptr<RingGSWAccumulator> ACCscheme{nullptr};
    std::shared_ptr<RingLWEHomTrace> HomTrace{nullptr};
    std::shared_ptr<RingLWESchemeSwitch> SchemeSwitch{nullptr};
};
}
#endif