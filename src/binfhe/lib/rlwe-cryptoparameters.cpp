#include "rlwe-cryptoparameters.h"

namespace lbcrypto{
void RLWECryptoParams::PreCompute(bool signEval) {

    //Computes baseHT^i
    if (signEval){
    }
    else{
        m_HTpower.reserve(m_EXdigitsHT);
        NativeInteger vTemp{1};
        for(uint32_t i = 0; i < m_EXdigitsHT; ++i){
            m_HTpower.push_back(vTemp);
            vTemp = vTemp.ModMulFast(NativeInteger(m_baseHT), m_Q);
        }
    }

    m_AHTpower.reserve(m_digitsHT);
    NativeInteger vTemp = NativeInteger(static_cast<BasicInteger>(std::ceil(m_Q.ConvertToDouble() / m_HTpower[m_digitsHT].ConvertToDouble())));
    for(uint32_t i = 0; i < m_digitsHT; ++i){
        m_AHTpower.push_back(vTemp);
        vTemp = vTemp.ModMulFast(NativeInteger(m_baseHT), m_Q);
    }

    //Computes baseSS^i
    if (signEval){
    }
    else{
        m_SSpower.reserve(m_EXdigitsSS);
        NativeInteger vTemp{1};
        for(uint32_t i = 0; i < m_EXdigitsSS; ++i){
            m_SSpower.push_back(vTemp);
            vTemp = vTemp.ModMulFast(NativeInteger(m_baseSS), m_Q);
        }
    }

    m_ASSpower.reserve(m_digitsSS);
    vTemp = NativeInteger(static_cast<BasicInteger>(std::ceil(m_Q.ConvertToDouble() / m_SSpower[m_digitsSS].ConvertToDouble())));
    for(uint32_t i = 0; i < m_digitsHT; ++i){
        m_ASSpower.push_back(vTemp);
        vTemp = vTemp.ModMulFast(NativeInteger(m_baseSS), m_Q);
    }

}
}
