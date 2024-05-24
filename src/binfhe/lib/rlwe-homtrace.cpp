#include "rlwe-homtrace.h"

namespace lbcrypto{
RLWEHomTraceKey RingLWEHomTrace::KeyGenHT(const std::shared_ptr<RLWECryptoParams>& params,
                                                    const NativePoly& skNTT) const {
    auto N = params->GetN();

    //the number of automorphism
    uint32_t numAuto = static_cast<uint32_t>(log2(N));

    //Homtarce key is composed with numAuto Auto keys and each Auto key is a RGSW ciphertext
    RLWEHomTraceKey ek = std::make_shared<RLWEHomTraceKeyImpl>(1, 1, numAuto);
    for (usint i = 0; i < numAuto; i++){
        (*ek)[0][0][i] = KeyGenAuto(params, skNTT, (N >> i) + 1);
    }
    return ek;
}

void RingLWEHomTrace::EvalHT(const std::shared_ptr<RLWECryptoParams>& params, ConstRLWEHomTraceKey& ek,
                             RLWECiphertext& ct) const {
    auto N = params->GetN();
    auto Q{params->GetQ()};
    //the number of automorphism
    uint32_t numAuto = static_cast<uint32_t>(log2(N));

    for (uint32_t i = 0; i < numAuto; i++){
        //copy ct
        std::vector<NativePoly> ct_identity(ct->GetElements());
        //automorphism of ct
        Automorphism(params, (N >> i) + 1, (*ek)[0][0][i], ct);
        ct->GetElements()[0] += ct_identity[0];
        ct->GetElements()[1] += ct_identity[1];
    }
}

void RingLWEHomTrace::SignedDigitDecompose(const std::shared_ptr<RLWECryptoParams>& params, const NativePoly& input,
                                           std::vector<NativePoly>& output) const {
    auto Q = params->GetQ(); 
    auto Q_int{Q.ConvertToInt<NativeInteger::SignedNativeInt>()};
    auto QHalf = Q.ConvertToInt<BasicInteger>() >> 1;
    auto baseHT = params->GetBaseHT();
    //the bits of each digit
    auto gBits{static_cast<NativeInteger::SignedNativeInt>(__builtin_ctz(baseHT))};
    //approximate length of homtrace
    uint32_t digitsHT{params->GetDigitsHTA()};

    //ignore bits
    uint32_t ignore_bits = 54 - gBits * digitsHT;
    //the number of bits of approximate decomposition remain
    auto gBitsMaxBits{static_cast<NativeInteger::SignedNativeInt>(NativeInteger::MaxBits() - ignore_bits)};
    uint32_t N{params->GetN()};
    
    auto gBitsMaxBits0{static_cast<NativeInteger::SignedNativeInt>(NativeInteger::MaxBits() - gBits)};

    for (uint32_t k{0}; k < N; ++k){
        auto t0{input[k].ConvertToInt<BasicInteger>()};
        auto d0{static_cast<NativeInteger::SignedNativeInt>(t0 < QHalf ? t0 : t0 - Q_int)};
        
        //the bits should ignore
        auto r0 = d0;
    
        r0 = (d0 << gBitsMaxBits) >> gBitsMaxBits;
        d0 = (d0 - r0) >> ignore_bits;
        
        for (uint32_t d{0}; d < digitsHT; ++d){
            r0 = (d0 << gBitsMaxBits0) >> gBitsMaxBits0;
            d0 = (d0 - r0) >> gBits;
            if (r0 < 0)
                r0 += Q_int;
            output[d + 0][k] += r0;
        }
    }
}

RingGSWEvalKey RingLWEHomTrace::KeyGenAuto(const std::shared_ptr<RLWECryptoParams>& params, const NativePoly& skNTT,
                                           uint32_t k) const {
    //powers of baseHT
    auto HTpow{params->GetAHTPower()};

    //the k-th automotphism of sk
    auto skAuto{skNTT.AutomorphismTransform(k)};

    //the HT length of approxiamte decomposition 
    uint32_t digitsHT{params->GetDigitsHTA()};
    RingGSWEvalKeyImpl result(digitsHT, 2);

    //the HT length of exact decomposition
    NativeInteger Q{params->GetQ()};

    auto polyparams = params->GetPolyParams();

    DiscreteUniformGeneratorImpl<NativeVector> dug;

    for (uint32_t i = 0; i < digitsHT; ++i){
        result[i][0] = NativePoly(dug, polyparams, EVALUATION);
        result[i][1] = NativePoly(params->GetHTDgg(), polyparams, EVALUATION) - skAuto * HTpow[i];
        result[i][1] += (result[i][0] * skNTT);
    }

    return std::make_shared<RingGSWEvalKeyImpl>(result);
}


void RingLWEHomTrace::Automorphism(const std::shared_ptr<RLWECryptoParams>& params, const uint32_t& a,
                                   ConstRingGSWEvalKey& ak, RLWECiphertext& ct) const {
    uint32_t N{params->GetN()};
    std::vector<usint> vec(N);
    PrecomputeAutoMap(N, a, &vec);
    ct->GetElements()[1] = ct->GetElements()[1].AutomorphismTransform(a, vec); //auto of b

    NativePoly cta(ct->GetElements()[0]);
    cta = cta.AutomorphismTransform(a, vec);//cta is evaluation format
    cta.SetFormat(COEFFICIENT);

    ct->GetElements()[0].SetValuesToZero();//now ct is (0,b)

    auto polyparams = params->GetPolyParams();
    uint32_t digitsHT{(params->GetDigitsHTA())};
    std::vector<NativePoly> dcta(digitsHT, NativePoly(polyparams, Format::COEFFICIENT, true));
    SignedDigitDecompose(params, cta, dcta);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(digitsHT))
    for(uint32_t d = 0; d < digitsHT; ++d){
        dcta[d].SetFormat(Format::EVALUATION);
    }

    //ct = (0,b) + dct * ak (matric product)
    const std::vector<std::vector<NativePoly>>& ev = ak->GetElements();
    for (uint32_t d = 0; d < digitsHT; ++d){
        ct->GetElements()[0] += (dcta[d] * ev[d][0]);
    }
    
    for (uint32_t d = 0; d < digitsHT; ++d){
        ct->GetElements()[1] += (dcta[d] * ev[d][1]);
    }
}
}  // namespace lbcrypto