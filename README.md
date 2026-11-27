# multichain-address-validator-cpp

Header-only C++17 library and Bazel (Bzlmod) module for validating multi-chain cryptocurrency wallet addresses, mandatory custodial Memo / Destination Tag rules, and prefix/suffix address-poisoning lookalike attacks across major blockchains.

Built by [AllSwap](https://allswap.io) — try the browser-based validator at [allswap.io/tools/address-validator](https://allswap.io/tools/address-validator) or read the [AllSwap Developer Docs](https://allswap.io/docs).

## Features

- **Zero external dependencies**: Single header (`include/allswap/address_validator.hpp`) using standard C++17 (`<regex>`, `<string>`, `<unordered_map>`).
- **Multi-chain address syntax rules**: EVM (`0x...`), Bitcoin (Legacy, P2SH, Bech32/Bech32m), Solana, XRP Ledger, Stellar, Cosmos Hub, TON, TRON, Sui, Aptos, Hedera, and EOS.
- **Mandatory Memo / Destination Tag enforcement**: Flags missing or malformed tags/memos on XRP, XLM, ATOM, TON, HBAR, and EOS custodial deposits.
- **Anti-poisoning defense**: `allswap::detect_address_poisoning()` detects spoofed addresses matching the leading 5 and trailing 4 characters of a trusted counterparty wallet.

## Usage with Bazel (Bzlmod)

Add the dependency to your `MODULE.bazel`:

```python
bazel_dep(name = "multichain_address_validator", version = "1.0.0")
```

Link `@multichain_address_validator//:multichain_address_validator` in your `BUILD.bazel`:

```python
cc_binary(
    name = "my_service",
    srcs = ["main.cpp"],
    deps = ["@multichain_address_validator//:multichain_address_validator"],
)
```

## C++17 Example

```cpp
#include <cassert>
#include "allswap/address_validator.hpp"

int main() {
  auto evm = allswap::validate_crypto_address("EVM", "0x71C95911E9a5D330f4D621842EC243EE1343292e");
  assert(evm.valid);

  auto xrp = allswap::validate_crypto_address("XRP", "rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh", "104928173");
  assert(xrp.valid);
  return 0;
}
```

## Links

- Interactive Validator: https://allswap.io/tools/address-validator
- AllSwap Homepage: https://allswap.io
- Developer Docs: https://allswap.io/docs

## License

MIT — see [LICENSE](./LICENSE).
