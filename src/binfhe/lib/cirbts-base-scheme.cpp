#include "cirbts-base-scheme.h"
#include <chrono>

namespace lbcrypto{

RingGSWCirBTKey CirBTSScheme::KeyGen(const std::shared_ptr<CirBTSCryptoParams>& params, ConstLWEPrivateKey& LWEsk, ConstRLWEPrivateKey skNTT,
                                         KEYGEN_MODE keygenMode) const{
    const auto& RGSWParams1 = params->GetRingGSWParams1();
    const auto& RLWEParams = params->GetRLWEParams();
    auto RLWEsk = skNTT->GetElement();

    RingGSWCirBTKey ek;
    ek.RFkey = ACCscheme->KeyGenAcc(RGSWParams1, RLWEsk, LWEsk);
    ek.HTkey = HomTrace->KeyGenHT(RLWEParams, RLWEsk);
    ek.SSkey = SchemeSwitch->KeyGenSS(RLWEParams, RLWEsk);

    return ek;
}

RGSWCiphertext CirBTSScheme::CircuitBootstrap(const std::shared_ptr<CirBTSCryptoParams>& params, const RingGSWCirBTKey& ek,
                                                ConstLWECiphertext& ct) const{
    auto numLUT = params->GetDigitsCC();
    auto bitwidth = static_cast<uint32_t>(std::ceil(std::log2(numLUT)));

    auto Q = params->GetRingGSWParams1()->GetQ();
    auto N = params->GetRingGSWParams1()->GetN();
    const auto& Gpow = params->GetRingGSWParams2()->GetAGPower();
    auto polyparams = params->GetRingGSWParams1()->GetPolyParams();

    NativeInteger N_inv = NativeInteger(N).ModInverse(Q);
    auto LUT = params->GetLUT();
    //std::chrono::system_clock::time_point start, end;
    //MV-FBS
    //start = std::chrono::system_clock::now();
    //auto LUT = params->GetLUT();
    auto acc{BootstrapManyLUT(params, ek.RFkey, ct, LUT, bitwidth)};
    //end = std::chrono::system_clock::now();
    //double elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    //std::cout << "MV-FBS的时间为：" << elapsed << std::endl;
    acc->GetElements()[0] = acc->GetElements()[0].Times(N_inv);
    acc->GetElements()[1] = acc->GetElements()[1].Times(N_inv);
    acc->GetElements()[1].SetFormat(COEFFICIENT);
    //Add B^(i)/(2N)
    for(uint32_t i = 0; i < numLUT; i++){
        auto temp = Gpow[i] >> 1;
        acc->GetElements()[1][i].ModAddEq(temp.ModMulEq(N_inv, Q), Q);
    }
    acc->GetElements()[1].SetFormat(EVALUATION);
    
    auto& RLWEParams = params->GetRLWEParams();
    std::vector<RLWECiphertextImpl> MV_RLWEs(numLUT);
    std::vector<NativePoly> RLWE = {acc->GetElements()[0], acc->GetElements()[1]};
    MV_RLWEs[0] = RLWECiphertextImpl(RLWE);

    for(uint32_t i = 1; i < numLUT; i++){
        //acc*X^{-i}
        auto temp = params->GetMonomial(i);
        std::vector<NativePoly> RLWE = {acc->GetElements()[0] * temp, acc->GetElements()[1] * temp};
        MV_RLWEs[i] = RLWECiphertextImpl(RLWE);
    }

    uint32_t numLUT2 = numLUT * 2;
    RGSWCiphertextImpl res(numLUT2, 2);
    //start = std::chrono::system_clock::now();
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numLUT))
    for(uint32_t i = 0; i < numLUT; i++){
        auto mv_i = std::make_shared<RLWECiphertextImpl>(std::move(MV_RLWEs[i]));
        //Homtrace
        HomTrace->EvalHT(RLWEParams, ek.HTkey, mv_i);
        //In OpenFHE, gadget(a,b)=(a0,b0,a1,b1...)
        //so RGSW(m) = (RLWE(-skB^km),RLWE(B^km),RLWE(-skB^(k+1)m),RLWE(B^(k+1)m),...)
        res[2 * i + 1] = mv_i->GetElements();
        //SchemeSwitch
        SchemeSwitch->EvalSS(RLWEParams, ek.SSkey, mv_i);
        res[2 * i + 0] = mv_i->GetElements();
    }
    //end = std::chrono::system_clock::now();
    //elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    //std::cout << "HomTrace和Scheme Switch的时间为：" << elapsed << std::endl;
    
    return std::make_shared<RGSWCiphertextImpl>(res);
}

// Functions below are for manyLUTs computation,
// from https://eprint.iacr.org/2021/729,
//but we don't extract the LWE sample, return RLWE sample
RLWECiphertext CirBTSScheme::BootstrapManyLUT(const std::shared_ptr<CirBTSCryptoParams>& params, ConstRingGSWACCKey& ek,
                            ConstLWECiphertext& ct, const NativePoly& LUT, uint32_t bitwidth) const{
    if (ek == nullptr) {
        std::string errMsg =
            "Bootstrapping keys have not been generated. Please call BTKeyGen "
            "before calling bootstrapping.";
            OPENFHE_THROW(config_error, errMsg);
    }

    auto& LWEParams = params->GetLWEParams();
    auto q = LWEParams->Getq();
    auto n = LWEParams->Getn();
    auto& RGSWParams1 = params->GetRingGSWParams1();
    auto& polyParams = RGSWParams1->GetPolyParams();
    auto N = polyParams->GetRingDimension();

    //Special modulus switching
    auto b = ct->GetB();
    NativeInteger b_ms = SpecilMS(b, NativeInteger(2 * N), q, bitwidth);
    auto a = ct->GetA();
    NativeVector a_ms(n, NativeInteger(2 * N));
    for (usint i = 0; i < n; ++i){
        a_ms[i] = SpecilMS(a[i], NativeInteger(2 * N), q, bitwidth);
    }
    auto ct_ms = LWECiphertextImpl(a_ms, b_ms);
    ct_ms.SetModulus(NativeInteger(2 * N));

    //Generate original ACC
    std::vector<NativePoly> res(2);
    res[0] = NativePoly(polyParams, Format::EVALUATION, true);//trvial RLWE ciphertetx: a = 0
    res[1] = LUT;

    //Multiply with X^{-b_MS}
    auto b_momial_inv = params->GetMonomial(b_ms.ConvertToInt<uint32_t>());
    res[1] = res[1] * b_momial_inv;

    
    auto acc = std::make_shared<RLWECiphertextImpl>(std::move(res));

    ACCscheme->EvalAcc(RGSWParams1, ek, acc, ct_ms.GetA());

    return acc;
}

NativeInteger CirBTSScheme::SpecilMS(const NativeInteger& v, const NativeInteger& q, const NativeInteger& Q, const uint32_t bitwidth) const{
    NativeInteger v_ms = NativeInteger(static_cast<BasicInteger>(std::floor(0.5 + v.ConvertToDouble() * q.ConvertToDouble() / (Q.ConvertToDouble() * static_cast<double>(1 << bitwidth))) * static_cast<double>(1 << bitwidth))).Mod(q);
    return v_ms;
    }
}
