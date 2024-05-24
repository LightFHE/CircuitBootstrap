#ifndef _RLWE_SCHEMESWITCHKEY_H_
#define _RLWE_SCHEMESWITCHKEY_H_

#include "rgsw-evalkey.h"

namespace lbcrypto{

//scheme switching key is a half GSW ciphertext
//RingGSWEvalKey is GSW ciphertext
using RLWESchemeSwitchKeyImpl = RingGSWEvalKeyImpl;
using RLWESchemeSwitchKey = std::shared_ptr<RLWESchemeSwitchKeyImpl>;
using ConstRLWESchemeSwitchKey = const std::shared_ptr<RLWESchemeSwitchKeyImpl>;
}
#endif