#ifndef _RLWE_PRIVATEKEY_H_
#define _RLWE_PRIVATEKEY_H_

#include "lattice/lat-hal.h"
#include <utils/serializable.h>

#include <memory>

namespace lbcrypto {

class RLWEPrivateKeyImpl;

using RLWEPrivateKey = std::shared_ptr<RLWEPrivateKeyImpl>;
using ConstRLWEPrivateKey = const std::shared_ptr<RLWEPrivateKeyImpl>;

/**
 * @brief Class that stores the RLWE scheme secret key; contains a polynomial
 */
class RLWEPrivateKeyImpl {
public:
    RLWEPrivateKeyImpl() = default;

    explicit RLWEPrivateKeyImpl(const NativePoly& s) : m_s(s) {}

    const NativePoly& GetElement() const {
        return m_s;
    }

    void SetElement(const NativePoly& s) {
        m_s = s;
    }

    uint32_t GetRingDimension() const {
        return m_s.GetRingDimension();
    }

    const NativeInteger& GetModulus() const {
        return m_s.GetModulus();
    }

private:
    NativePoly m_s;

};

}
#endif