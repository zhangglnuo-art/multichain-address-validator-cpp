#include <cassert>
#include "allswap/address_validator.hpp"

int main() {
  auto evm = allswap::validate_crypto_address("EVM", "0x71C95911E9a5D330f4D621842EC243EE1343292e");
  assert(evm.valid);

  auto xrp_no_memo = allswap::validate_crypto_address("XRP", "rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh");
  assert(!xrp_no_memo.valid && xrp_no_memo.code == "MISSING_MANDATORY_MEMO");

  auto xrp_ok = allswap::validate_crypto_address("XRP", "rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh", "104928173");
  assert(xrp_ok.valid);

  auto poisoned = allswap::validate_crypto_address(
      "EVM",
      "0x71C950000000000000000000000000000000292e",
      "",
      "0x71C95911E9a5D330f4D621842EC243EE1343292e");
  assert(!poisoned.valid && poisoned.code == "ADDRESS_POISONING_ALERT");

  return 0;
}
