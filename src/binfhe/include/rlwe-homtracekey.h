#ifndef _RLWE_HOMTRACEKEY_H_
#define _RLWE_HOMTRACEKEY_H_

#include "rgsw-acckey.h"

namespace lbcrypto{
using RLWEHomTraceKeyImpl = RingGSWACCKeyImpl;
using RLWEHomTraceKey = std::shared_ptr<RLWEHomTraceKeyImpl>;
using ConstRLWEHomTraceKey = const std::shared_ptr<RLWEHomTraceKeyImpl>;
}
#endif