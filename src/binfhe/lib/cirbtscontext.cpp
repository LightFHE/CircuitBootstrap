#include "cirbtscontext.h"
#include <unordered_map>

namespace lbcrypto{ 

void CirBTSContext::GenerateCirBTSContext(CirBTS_PARAMSET set, BINFHE_METHOD method) {
    constexpr double STD_DEV = 3.2;

    const std::unordered_map<CirBTS_PARAMSET, CirBTSContextParams> CircuitParamsMap({
            //                          numberBits|cyclOrder|latticeParam|  mod|   stdDev| BaseEP|  DigitsEP| BaseHT| DigitsHT| BaseSS| DigitsSS|BaseCC| DigitsCC|keyDist0|keyDist2 
        { STD128_CircuitBootstrap_CMUX_1, {54,      4096,      571,        1024,  STD_DEV,  1 << 17,   2,    1 << 17,   2,    1 << 28,    1,    1 << 1,  8,   UNIFORM_BINARY, UNIFORM_BINARY} },
        { STD128_CircuitBootstrap_CMUX_2, {54,      4096,      571,        1024,  STD_DEV,  1 << 13,   3,    1 << 17,   2,    1 << 28,    1,    1 << 3,  4,   UNIFORM_BINARY, UNIFORM_BINARY} },
        { STD128_CircuitBootstrap_CMUX_3, {54,      4096,      571,        1024,  STD_DEV,  1 << 13,   3,    1 << 17,   2,    1 << 28,    1,    1 << 2,  8,   UNIFORM_BINARY, UNIFORM_BINARY} },
        { STD128_CircuitBootstrap_CMUX_4, {54,      4096,      571,        1024,  STD_DEV,  1 << 10,   4,    1 << 13,   3,    1 << 28,    1,    1 << 2,  8,   UNIFORM_BINARY, UNIFORM_BINARY} },
    });

    auto search = CircuitParamsMap.find(set);
    if (CircuitParamsMap.end() == search ){
        std::string errMsg("ERROR: Unknown parameter set [" + std::to_string(set) + "] for circuitbootstrap");
        OPENFHE_THROW(config_error, errMsg);
    }

    CirBTSContextParams params = search->second;

    //level 2 prime modulus 
    NativeInteger Q(LastPrime<NativeInteger>(params.numberBits, params.cyclOrder));

    usint ringDim = params.cyclOrder / 2;
    auto lweparams = std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q, params.mod,
                                                        params.stdDev, 1, params.keyDist0);
    auto rgswparams1 = std::make_shared<RingGSWCryptoParams>(ringDim, Q, params.mod, params.BaseEP, params.mod,
                                                             method, params.stdDev, params.DigitsEP, params.keyDist2, false, 10);
    auto rlweparams = std::make_shared<RLWECryptoParams>(params.cyclOrder, ringDim, Q, params.stdDev, params.BaseHT,
                                                        params.DigitsHT, params.BaseSS, params.DigitsSS, params.keyDist2);
    auto rgswparams2 = std::make_shared<RingGSWCryptoParams>(ringDim, Q, params.mod, params.BaseCC, params.mod,
                                                             method, params.stdDev, params.DigitsCC, params.keyDist2, false, 10);
    m_params = std::make_shared<CirBTSCryptoParams>(lweparams, rgswparams1, rlweparams, rgswparams2);
    m_cirbtsscheme = std::make_shared<CirBTSScheme>(method);
}

RLWEPrivateKey CirBTSContext::RLWEKeyGen() const{
    auto& RLWEParams = m_params->GetRLWEParams();
    if (RLWEParams->GetKeyDist() == GAUSSIAN)
        return m_RLWEscheme->KeyGenGaussian(RLWEParams->GetN(), RLWEParams->GetQ(), 3.2);
    else if (RLWEParams->GetKeyDist() == UNIFORM_TERNARY)
    {
        return m_RLWEscheme->KeyGenTernary(RLWEParams->GetN(), RLWEParams->GetQ());
    }
    return m_RLWEscheme->KeyGenBinary(RLWEParams->GetN(), RLWEParams->GetQ());
}

LWEPrivateKey CirBTSContext::KeyGen() const{
    auto& LWEParams = m_params->GetLWEParams();
    if (LWEParams->GetKeyDist() == GAUSSIAN)
        return m_LWEscheme->KeyGenGaussian(LWEParams->Getn(), LWEParams->GetqKS());
    else if (LWEParams->GetKeyDist() == UNIFORM_TERNARY)
    {
        return m_LWEscheme->KeyGen(LWEParams->Getn(), LWEParams->GetqKS());
    }
    return m_LWEscheme->KeyGenBinary(LWEParams->Getn(), LWEParams->GetqKS());
}

LWECiphertext CirBTSContext::Encrypt(ConstLWEPrivateKey& sk, LWEPlaintext m, LWEPlaintextModulus p) const{
    const auto& LWEParams = m_params->GetLWEParams();
    LWECiphertext ct = m_LWEscheme->Encrypt(LWEParams, sk, m, p, LWEParams->Getq());
    return ct;
}

void CirBTSContext::Decrypt(ConstLWEPrivateKey& sk, ConstLWECiphertext& ct, LWEPlaintext* result, LWEPlaintextModulus p) const{
    auto&& LWEParams = m_params->GetLWEParams();
    m_LWEscheme->Decrypt(LWEParams, sk, ct, result, p);
}

void CirBTSContext::CirBTKeyGen(ConstLWEPrivateKey& sk, ConstRLWEPrivateKey skNTT, KEYGEN_MODE keygenMode){
    m_BTKey           = m_cirbtsscheme->KeyGen(m_params, sk, skNTT, keygenMode);
}

RGSWCiphertext CirBTSContext::CircuitBootstrapping(ConstLWECiphertext& ct) const{
    return m_cirbtsscheme->CircuitBootstrap(m_params, m_BTKey, ct);
}

}
