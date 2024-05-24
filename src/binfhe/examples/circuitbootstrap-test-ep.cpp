//Using external product to test the correctness of circuit bootstrapping
#include "cirbtscontext.h"
#include "rlwe-ske.h"

#include <chrono>

using namespace lbcrypto;

int main(){
    int loop = 1000;
    double time = 0;
    for (int l = 0; l < loop; l++){
        //Generate context of circuit bootstrapping
        auto cc = CirBTSContext();
        cc.GenerateCirBTSContext(STD128_CircuitBootstrap_CMUX_2, GINX);
        auto sk = cc.KeyGen();//level 0 secret key
        auto sk2 = cc.RLWEKeyGen();//level 2 secret key

        //Generate RLWE ciphertext of m1
        auto rlweParams = cc.GetParams()->GetRLWEParams();
        auto polyParams = rlweParams->GetPolyParams();
        auto N = polyParams->GetRingDimension();
        auto Q = polyParams->GetModulus();
        auto basecc = cc.GetParams()->GetRingGSWParams2()->GetBaseG();
        auto digitscc = cc.GetParams()->GetDigitsCC();
    
        BinaryUniformGeneratorImpl<NativeVector> bug;
        NativePoly m1p(bug, polyParams, COEFFICIENT);

        auto rlwecontext = RLWEEncryptionScheme();
        auto ct1 = rlwecontext.Encrypt(rlweParams, sk2, m1p, 2, Q);

        //Circuit bootstrapping of LWE(1)
        auto ct2 = cc.Encrypt(sk, 1);
        cc.CirBTKeyGen(sk, sk2);

        std::chrono::system_clock::time_point start, end;
        start = std::chrono::system_clock::now();

        auto ct_gsw = cc.CircuitBootstrapping(ct2);

        end = std::chrono::system_clock::now();

        double elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        //std::cout << elapsed << std::endl;
        time += elapsed;

        //RLWE and GSW external product
        std::vector<NativePoly> dct1(2 * digitscc, NativePoly(polyParams, COEFFICIENT, true));
        ct1->GetElements()[0].SetFormat(COEFFICIENT);
        ct1->GetElements()[1].SetFormat(COEFFICIENT);
        rlwecontext.SignedDigitDecompose(rlweParams, ct1, basecc, digitscc, dct1);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(2 * digitscc))
        for (uint32_t i = 0; i < (2 * digitscc); ++i)
            dct1[i].SetFormat(Format::EVALUATION);     

        std::vector<NativePoly> ct_cc(2, NativePoly(polyParams, EVALUATION, true));

        for (uint32_t i = 0; i < (2 * digitscc); ++i){
            ct_cc[0] += dct1[i] * ct_gsw->GetElements()[i][0];
            ct_cc[1] += dct1[i] * ct_gsw->GetElements()[i][1];
        }

        //Verify if ct_cc is the RLWE ciphertext of m1
        RLWECiphertextImpl ct_c(ct_cc);
        NativePoly m(polyParams, COEFFICIENT, false);
        rlwecontext.Decrypt(rlweParams, sk2, std::make_shared<RLWECiphertextImpl>(ct_c), &m, 2);

        for (uint32_t i = 0; i < N; i++){
            if (m[i].ConvertToInt() != m1p[i].ConvertToInt()){
                std::cerr << "Error: Circuit bootstrapping failure..." <<std::endl;
                return 1;
            }
        }
    }
    std::cout << "Circuit bootstrapping and external product are successful!" << std::endl;
    std::cout << "电路自举时间为：" << time/loop << "ms" << std::endl; 
    return 0;
}