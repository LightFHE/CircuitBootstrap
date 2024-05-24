#include "rlwe-ske.h"

#include <memory>

namespace lbcrypto
{
RLWEPrivateKey RLWEEncryptionScheme::KeyGenBinary(usint dimen, const NativeInteger& modulus) const{
    BinaryUniformGeneratorImpl<NativeVector> bug;
    //construct polyParams
    auto polyParams = std::make_shared<ILNativeParams>(dimen << 1, modulus);
    return std::make_shared<RLWEPrivateKeyImpl>(RLWEPrivateKeyImpl(NativePoly(bug, polyParams, EVALUATION)));
}

RLWEPrivateKey RLWEEncryptionScheme::KeyGenTernary(usint dimen, const NativeInteger& modulus) const {
    TernaryUniformGeneratorImpl<NativeVector> tug;
    //construct polyParams
    auto polyParams = std::make_shared<ILNativeParams>(dimen << 1, modulus);
    return std::make_shared<RLWEPrivateKeyImpl>(RLWEPrivateKeyImpl(NativePoly(tug, polyParams, EVALUATION)));
}

RLWEPrivateKey RLWEEncryptionScheme::KeyGenGaussian(usint dimen, const NativeInteger& modulus, double std) const {
    DiscreteGaussianGeneratorImpl<NativeVector> dgg(std);
    //construct polyParams
    auto polyParams = std::make_shared<ILNativeParams>(dimen << 1, modulus);
    return std::make_shared<RLWEPrivateKeyImpl>(RLWEPrivateKeyImpl(NativePoly(dgg, polyParams, EVALUATION)));
}

RLWECiphertext RLWEEncryptionScheme::Encrypt(const std::shared_ptr<RLWECryptoParams>& params, ConstRLWEPrivateKey& sk,
                            NativePoly m, LWEPlaintextModulus p, NativeInteger mod) const{
    if (mod % p != 0 && mod.ConvertToInt() & (1 == 0)) {
        std::string errMsg = "ERROR: ciphertext modulus q needs to be divisible by plaintext modulus p.";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }
    
    NativePoly s = sk->GetElement();
    
    std::vector<NativePoly> res(2);

    auto polyparams = params->GetPolyParams();
    NativePoly encode_m = m.Mod(p) * (mod / p);
    encode_m.SetFormat(EVALUATION);
    res[1] = encode_m + NativePoly(params->GetDgg(), polyparams, EVALUATION);

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    res[0] = NativePoly(dug, polyparams, EVALUATION);

    res[1] += res[0] * s;
    
    RLWECiphertextImpl ct = RLWECiphertextImpl(res);
    return std::make_shared<RLWECiphertextImpl>(ct);
}

void RLWEEncryptionScheme::Decrypt(const std::shared_ptr<RLWECryptoParams>& params, ConstRLWEPrivateKey& sk,
                    ConstRLWECiphertext& ct, NativePoly* result, LWEPlaintextModulus p) const{
    const NativeInteger& mod = params->GetQ();
    if (mod % p != 0 && mod.ConvertToInt() & (1 == 0)){
         std::string errMsg = "ERROR: ciphertext modulus q needs to be divisible by plaintext modulus p.";
         OPENFHE_THROW(not_implemented_error, errMsg);
    }
    NativePoly a = ct->GetElements()[0];
    NativePoly b = ct->GetElements()[1];

    auto N = params->GetN();
    auto s = sk->GetElement();
    NativePoly r = b - a * s;
    r.SetFormat(COEFFICIENT);
    for (usint i = 0; i < N; i++){
        //rvalues[i] = rvalues[i].ModAddFastEq((mod / (p * 2)), mod);
        auto temp = r[i].DivideAndRound((mod / p)).ConvertToInt();
        r[i].SetValue(NativeInteger(temp % p));
    }
    *result = r;
}

void RLWEEncryptionScheme::SignedDigitDecompose(const std::shared_ptr<RLWECryptoParams>& params,
                                                ConstRLWECiphertext& input, const uint32_t base, const uint32_t digits,
                                                std::vector<NativePoly>& output) const {
    auto Q{params->GetQ()};
    auto Q_int{Q.ConvertToInt<NativeInteger::SignedNativeInt>()};
    auto QHalf = Q.ConvertToInt<BasicInteger>() >> 1;
    auto gBits{static_cast<NativeInteger::SignedNativeInt>(__builtin_ctz(base))};

    //the bits should be ignored
    uint32_t ignore_bits = 54 - digits * gBits;
    //the bits should be remained
    auto gBitsMaxBits{static_cast<NativeInteger::SignedNativeInt>(NativeInteger::MaxBits() - ignore_bits)};
    // approximate gadget decomposition is used;
    uint32_t digitsG2{digits << 1};
    uint32_t N{params->GetN()};

    auto gBitsMaxBits0{static_cast<NativeInteger::SignedNativeInt>(NativeInteger::MaxBits() - gBits)};
    
    auto cta = input->GetElements()[0];
    auto ctb = input->GetElements()[1];

    for (uint32_t k{0}; k < N; ++k) {
        auto t0{cta[k].ConvertToInt<BasicInteger>()};
        auto d0{static_cast<NativeInteger::SignedNativeInt>(t0 < QHalf ? t0 : t0 - Q_int)};
        auto t1{ctb[k].ConvertToInt<BasicInteger>()};
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

} // namespace lbcrypto
