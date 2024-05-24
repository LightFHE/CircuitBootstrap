//Using decryption of rgsw to test the correctness of circuit bootstrapping
//The correctness of parameter set 'STD128_CircuitBootstrap_CMUX_1' can only be verified in this way.
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
        cc.GenerateCirBTSContext(STD128_CircuitBootstrap_CMUX_1, GINX);
        auto sk = cc.KeyGen();//level 0 secret key
        auto sk2 = cc.RLWEKeyGen();//level 2 secret key

        //LWE(1)
        auto ct = cc.Encrypt(sk, 1);

        //Generate circuit bootstrapping key
        cc.CirBTKeyGen(sk, sk2);

        std::chrono::system_clock::time_point start, end;
        start = std::chrono::system_clock::now();

        //Circuit bootstrapping
        auto ct_gsw = cc.CircuitBootstrapping(ct);

        end = std::chrono::system_clock::now();

        double elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        //std::cout << elapsed << std::endl;
        time += elapsed;

        //Verify if ct_rgsw is the ciphertext of 1  
        auto rlweParams = cc.GetParams()->GetRLWEParams();
        auto polyParams = rlweParams->GetPolyParams();
        auto N = polyParams->GetRingDimension();
        auto digitscc = cc.GetParams()->GetDigitsCC();
        auto basecc_pow = cc.GetParams()->GetRingGSWParams2()->GetAGPower();
        
        auto rlwect = ct_gsw->GetElements()[2 * digitscc - 1];
        auto m_last = rlwect[1] - rlwect[0] * sk2->GetElement();
        m_last.SetFormat(COEFFICIENT);
        for (uint32_t i = 0; i < N; i++){
            auto temp = m_last[i].DivideAndRound(basecc_pow[digitscc - 1]).ConvertToInt();
            temp = temp % 2;
            if ( i == 0 && temp != 1){
                std::cerr << "Error: Circuit bootstrapping failure..." <<std::endl;
                return 1;
            }
            else if (i != 0 && temp != 0){
                std::cerr << "Error: Circuit bootstrapping failure..." <<std::endl;
                return 1;
            }
        }

    }
    std::cout << "Circuit bootstrapping and leveled computation are successful!" << std::endl;
    std::cout <<"The time of circiutbootstrapping: " <<  time/loop << "ms" << std::endl;
    return 0;
}