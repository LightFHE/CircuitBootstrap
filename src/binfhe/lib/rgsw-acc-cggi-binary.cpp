#include "rgsw-acc-cggi-binary.h"

#include <string>

namespace lbcrypto {

// Key generation as described in Section 4 of https://eprint.iacr.org/2014/816
RingGSWACCKey RingGSWAccumulatorCGGI2::KeyGenAcc(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                const NativePoly& skNTT, ConstLWEPrivateKey& LWEsk) const {
    auto sv    = LWEsk->GetElement();
    uint32_t n = sv.GetLength();
    auto ek    = std::make_shared<RingGSWACCKeyImpl>(1, 1, n);
    auto& ek00 = (*ek)[0][0];

    // handles binary secret
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(n))
    for (uint32_t i = 0; i < n; ++i) {
        auto s  = sv[i].ConvertToInt();
        ek00[i] = KeyGenCGGI(params, skNTT, s);
    }
    return ek;
}

void RingGSWAccumulatorCGGI2::EvalAcc(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWACCKey& ek,
                                     RLWECiphertext& acc, const NativeVector& a) const {
    size_t n{a.GetLength()};
    auto mod{a.GetModulus()};
    auto MbyMod{NativeInteger(2 * params->GetN()) / mod};
    for (size_t i = 0; i < n; ++i) {
        AddToAccCGGI(params, (*ek)[0][0][i], a[i] * MbyMod, acc);
    }
}

// Encryption for the CGGI variant, as described in https://eprint.iacr.org/2020/086
RingGSWEvalKey RingGSWAccumulatorCGGI2::KeyGenCGGI(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                  const NativePoly& skNTT, LWEPlaintext m) const {
    const auto& Gpow       = params->GetAGPower();
    const auto& polyParams = params->GetPolyParams();

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeInteger Q{params->GetQ()};

    // approximate gadget decomposition is used
    uint32_t digits = params->GetDigitsGA();
    uint32_t digitsG2{digits << 1};

    std::vector<NativePoly> tempA(digitsG2, NativePoly(dug, polyParams, Format::COEFFICIENT));
    RingGSWEvalKeyImpl result(digitsG2, 2);

    for (uint32_t i = 0; i < digitsG2; ++i) {
        result[i][0] = tempA[i];
        tempA[i].SetFormat(Format::EVALUATION);
        result[i][1] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);
        if (m)
            result[i][i & 0x1][0].ModAddFastEq(Gpow[i >> 1], Q);
        result[i][0].SetFormat(Format::EVALUATION);
        result[i][1].SetFormat(Format::EVALUATION);
        result[i][1] += (tempA[i] *= skNTT);
    }
    return std::make_shared<RingGSWEvalKeyImpl>(result);
}

// CGGI Accumulation as described in https://eprint.iacr.org/2020/086
// We optimize the algorithm by multiplying the monomial after the external product
// This reduces the number of polynomial multiplications which further reduces the runtime
void RingGSWAccumulatorCGGI2::AddToAccCGGI(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWEvalKey& ek,
                                             const NativeInteger& a, RLWECiphertext& acc) const {
    std::vector<NativePoly> ct(acc->GetElements());
    ct[0].SetFormat(Format::COEFFICIENT);
    ct[1].SetFormat(Format::COEFFICIENT);
   
    // approximate gadget decomposition is used
    uint32_t digitsG2{(params->GetDigitsGA()) << 1};
    std::vector<NativePoly> dct(digitsG2, NativePoly(params->GetPolyParams(), Format::COEFFICIENT, true));

    SignedDigitDecompose2(params, ct, dct);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(digitsG2))
    for (uint32_t i = 0; i < digitsG2; ++i)
        dct[i].SetFormat(Format::EVALUATION);

    // obtain monomial(index)
    uint32_t indexPos{a.ConvertToInt<uint32_t>()};
    const NativePoly& monomial = params->GetMonomial(indexPos);

    // acc = acc + dct * ek * monomial;
    // uses in-place * operators for the last call to dct[i] to gain performance
    // improvement. 
    // TODO (dsuponit): benchmark cases with operator*() and operator*=(). Make a copy of dct?

    const std::vector<std::vector<NativePoly>>& ev(ek->GetElements());
    NativePoly tmp(dct[0] * ev[0][0]);
    for (uint32_t i = 1; i < digitsG2; ++i)
        tmp += (dct[i] * ev[i][0]);
    acc->GetElements()[0] += (tmp *= monomial);
    tmp = (dct[0] * ev[0][1]);
    for (uint32_t i = 1; i < digitsG2; ++i)
        tmp += (dct[i] * ev[i][1]);
    acc->GetElements()[1] += (tmp *= monomial);
}

void RingGSWAccumulatorCGGI2::SignedDigitDecompose2(const std::shared_ptr<RingGSWCryptoParams>& params, const std::vector<NativePoly>& input,
                              std::vector<NativePoly>& output) const{
    auto Q{params->GetQ()};
    auto Q_int{Q.ConvertToInt<NativeInteger::SignedNativeInt>()};
    auto QHalf = Q.ConvertToInt<BasicInteger>() >> 1;
    auto base = params->GetBaseG();
    auto gBits{static_cast<NativeInteger::SignedNativeInt>(__builtin_ctz(base))};

    //the length of approximate decomposition
    auto digits = params->GetDigitsGA();
    //the bits should be ignored
    uint32_t ignore_bits = 54 - digits * gBits;
    //the bits should be remained
    auto gBitsMaxBits{static_cast<NativeInteger::SignedNativeInt>(NativeInteger::MaxBits() - ignore_bits)};
    // approximate gadget decomposition is used;
    uint32_t digitsG2{digits << 1};
    uint32_t N{params->GetN()};

    auto gBitsMaxBits0{static_cast<NativeInteger::SignedNativeInt>(NativeInteger::MaxBits() - gBits)};

    for (uint32_t k{0}; k < N; ++k) {
        auto t0{input[0][k].ConvertToInt<BasicInteger>()};
        auto d0{static_cast<NativeInteger::SignedNativeInt>(t0 < QHalf ? t0 : t0 - Q_int)};
        auto t1{input[1][k].ConvertToInt<BasicInteger>()};
        auto d1{static_cast<NativeInteger::SignedNativeInt>(t1 < QHalf ? t1 : t1 - Q_int)};

        auto r0 = (d0 << gBitsMaxBits) >> gBitsMaxBits;
        d0 = (d0 - r0) >> ignore_bits;

        auto r1 = (d1 << gBitsMaxBits) >> gBitsMaxBits;
        d1 = (d1 - r1) >> ignore_bits;


        for (uint32_t d{0}; d < digitsG2; d += 2) {
            r0 = (d0 << gBitsMaxBits0) >> gBitsMaxBits0;
            d0 = (d0 - r0) >> gBits;
            if (r0 < 0)
                r0 += Q_int;
            output[d + 0][k] += r0;

            r1 = (d1 << gBitsMaxBits0) >> gBitsMaxBits0;
            d1 = (d1 - r1) >> gBits;
            if (r1 < 0)
                r1 += Q_int;
            output[d + 1][k] += r1;
        }
    }                                
}

};  // namespace lbcrypto
