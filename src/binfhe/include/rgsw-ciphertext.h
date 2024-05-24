#ifndef _RGSW_CIPHERTEXT_H_
#define _RGSW_CIPHERTEXT_H_

#include "rgsw-evalkey.h"

namespace lbcrypto {

using RGSWCiphertextImpl = RingGSWEvalKeyImpl;
using RGSWCiphertext      = std::shared_ptr<RGSWCiphertextImpl>;
using ConstRGSWCiphertext = const std::shared_ptr<const RGSWCiphertextImpl>;

}  // namespace lbcrypto

#endif  // _RGSW_CIPHERTEXT_H_
