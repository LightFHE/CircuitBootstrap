#include "rlwe-schemeswitch.h"

namespace lbcrypto{
RLWESchemeSwitchKey RingLWESchemeSwitch::KeyGenSS(const std::shared_ptr<RLWECryptoParams>& params,
                                                  const NativePoly& skNTT) const {
    //sk^2
    NativePoly sk2 = skNTT * skNTT;

    //the power of baseSS
    auto SSpow{params->GetASSPower()};
    auto polyparams{params->GetPolyParams()};

    //approximate gadget decomposition is used
    uint32_t digitsSS{params->GetDigitsSSA()};

    RLWESchemeSwitchKeyImpl result(digitsSS, 2);

    DiscreteUniformGeneratorImpl<NativeVector> dug;

    for (uint32_t i = 0; i < digitsSS; i++){
        result[i][0] = NativePoly(dug, polyparams, Format::EVALUATION);
        result[i][1] = NativePoly(params->GetSSDgg(), polyparams, EVALUATION) + sk2 * SSpow[i];
        result[i][1] += (result[i][0] * skNTT);
    }

    return std::make_shared<RLWESchemeSwitchKeyImpl>(result);
}

void RingLWESchemeSwitch::EvalSS(const std::shared_ptr<RLWECryptoParams>& params, ConstRLWESchemeSwitchKey& ek,
                                 RLWECiphertext& ct) const {
    NativePoly cta = ct->GetElements()[0];
    NativePoly ctb = ct->GetElements()[1];
    cta.SetFormat(COEFFICIENT);

    auto polyparams{params->GetPolyParams()};

    //Generate the trivial ciphertext of -b*sk 
    ct->GetElements()[0] = ctb;
    ct->GetElements()[1].SetValuesToZero();

    auto digitsSS{params->GetDigitsSSA()};
    std::vector<NativePoly> dcta(digitsSS, NativePoly(polyparams, Format::COEFFICIENT, true));
    SignedDigitDecompose(params, cta, dcta);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(digitsSS))
    for(uint32_t d = 0; d < digitsSS; ++d){
        dcta[d].SetFormat(Format::EVALUATION);
    }

    const std::vector<std::vector<NativePoly>>& ev = ek->GetElements();
    for (uint32_t d = 0; d < digitsSS; ++d){
        ct->GetElements()[0] += (dcta[d] * ev[d][0]);
    }

    for (uint32_t d = 0; d < digitsSS; ++d){
        ct->GetElements()[1] += (dcta[d] * ev[d][1]);
    }

}

void RingLWESchemeSwitch::SignedDigitDecompose(const std::shared_ptr<RLWECryptoParams>& params, const NativePoly& input,
                                               std::vector<NativePoly>& output) const {
    auto QHalf{params->GetQ().ConvertToInt<BasicInteger>() >> 1};
    auto Q_int{params->GetQ().ConvertToInt<NativeInteger::SignedNativeInt>()};
    auto baseSS = params->GetBaseSS();
    //the bits of each digit
    auto gBits{static_cast<NativeInteger::SignedNativeInt>(__builtin_ctz(baseSS))};

    //approximate length of scheme switch
    uint32_t digitsSS{params->GetDigitsSSA()};

    //ignore bits
    uint32_t ignore_bits = 54 - digitsSS * gBits;
    //the number of bits of approximate decomposition remain
    auto gBitsMaxBits{static_cast<NativeInteger::SignedNativeInt>(NativeInteger::MaxBits() - ignore_bits)};
    
    uint32_t N{params->GetN()};
    
    auto gBitsMaxBits0{static_cast<NativeInteger::SignedNativeInt>(NativeInteger::MaxBits() - gBits)};

    for (uint32_t k{0}; k < N; ++k){
        auto t0{input[k].ConvertToInt<BasicInteger>()};
        auto d0{static_cast<NativeInteger::SignedNativeInt>(t0 < QHalf ? t0 : t0 - Q_int)};
        //the bits should ignore
        auto r0 = d0;
        if (ignore_bits != 0){
            r0 = (d0 << gBitsMaxBits) >> gBitsMaxBits;
            d0 = (d0 - r0) >> ignore_bits;
        }

        for (uint32_t d{0}; d < digitsSS; ++d){
            r0 = (d0 << gBitsMaxBits0) >> gBitsMaxBits0;
            d0 = (d0 - r0) >> gBits;
            if (r0 < 0)
                r0 += Q_int;
            output[d + 0][k] += r0;
        }
    }

}
}  // namespace lbcrypto