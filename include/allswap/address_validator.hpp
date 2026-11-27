#pragma once

#include <algorithm>
#include <cctype>
#include <regex>
#include <string>
#include <unordered_map>

namespace allswap {

struct ValidationResult {
  bool valid;
  std::string code;
  std::string chain;
  std::string message;
};

struct ChainRule {
  std::string name;
  std::string pattern;
  bool requires_memo;
  std::string memo_name;
  std::string memo_pattern;
};

inline std::string to_upper_ascii(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  return s;
}

inline std::string to_lower_ascii(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

inline std::string trim_ascii(const std::string& s) {
  size_t start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  size_t end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

inline const std::unordered_map<std::string, ChainRule>& chain_rules() {
  static const std::unordered_map<std::string, ChainRule> kRules = {
      {"EVM", {"Ethereum / Arbitrum / Base / Optimism / Polygon / BNB (EVM)", "^0x[a-fA-F0-9]{40}$", false, "None", ""}},
      {"BTC", {"Bitcoin (Legacy / SegWit / Taproot Bech32m)", "^(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,87})$", false, "None", ""}},
      {"SOL", {"Solana (Ed25519 Base58)", "^[1-9A-HJ-NP-Za-km-z]{32,44}$", false, "SPL Memo (Optional)", ""}},
      {"XRP", {"XRP Ledger (XRPL)", "^r[1-9A-HJ-NP-Za-km-z]{24,34}$", true, "Destination Tag (32-bit uint)", "^[0-9]{1,10}$"}},
      {"XLM", {"Stellar Lumens (StrKey)", "^G[A-Z2-7]{55}$", true, "Stellar Memo (up to 28 bytes)", "^.{1,28}$"}},
      {"ATOM", {"Cosmos Hub (Bech32)", "^cosmos1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38}$", true, "Cosmos Memo", "^.{1,256}$"}},
      {"TON", {"The Open Network (TON)", "^((EQ|UQ)[A-Za-z0-9_-]{46}|(0|-1):[a-fA-F0-9]{64})$", true, "TON Comment / Memo Tag", "^.{1,120}$"}},
      {"TRX", {"TRON (TVM Base58Check)", "^T[1-9A-HJ-NP-Za-km-z]{33}$", false, "None", ""}},
      {"SUI", {"Sui Network", "^0x[a-fA-F0-9]{64}$", false, "None", ""}},
      {"APT", {"Aptos Network", "^0x[a-fA-F0-9]{1,64}$", false, "None", ""}},
      {"HBAR", {"Hedera Hashgraph", "^0\\.0\\.[1-9][0-9]{0,9}$", true, "Hedera Memo (up to 100 bytes)", "^.{1,100}$"}},
      {"EOS", {"EOSIO / Vaulta", "^[a-z1-5.]{1,12}$", true, "EOS Memo", "^.{1,256}$"}},
  };
  return kRules;
}

inline bool detect_address_poisoning(const std::string& candidate, const std::string& trusted) {
  std::string a = to_lower_ascii(trim_ascii(candidate));
  std::string b = to_lower_ascii(trim_ascii(trusted));
  if (a.size() < 12 || b.size() < 12 || a == b) return false;
  return a.substr(0, 5) == b.substr(0, 5) && a.substr(a.size() - 4) == b.substr(b.size() - 4);
}

inline ValidationResult validate_crypto_address(const std::string& chain,
                                                const std::string& address,
                                                const std::string& memo = "",
                                                const std::string& trusted_address = "") {
  std::string code = to_upper_ascii(trim_ascii(chain));
  const auto& rules = chain_rules();
  auto it = rules.find(code);
  if (it == rules.end()) {
    return {false, "UNSUPPORTED_CHAIN", code, "Unsupported blockchain ticker: " + code};
  }
  const ChainRule& rule = it->second;
  std::string clean_addr = trim_ascii(address);
  std::string clean_memo = trim_ascii(memo);
  if (clean_addr.empty() || !std::regex_match(clean_addr, std::regex(rule.pattern))) {
    return {false, "INVALID_ADDRESS_SYNTAX", code, "Invalid " + rule.name + " wallet address format."};
  }
  if (rule.requires_memo) {
    if (clean_memo.empty()) {
      return {false, "MISSING_MANDATORY_MEMO", code, code + " custodial transfers require a mandatory " + rule.memo_name + "."};
    }
    if (!rule.memo_pattern.empty() && !std::regex_match(clean_memo, std::regex(rule.memo_pattern))) {
      return {false, "INVALID_MEMO_FORMAT", code, "Invalid " + rule.memo_name + " format for " + code + "."};
    }
  }
  std::string clean_trusted = trim_ascii(trusted_address);
  if (!clean_trusted.empty() && detect_address_poisoning(clean_addr, clean_trusted)) {
    return {false, "ADDRESS_POISONING_ALERT", code,
            "CRITICAL ALERT: Candidate address matches prefix & suffix of trusted reference address while differing in middle bytes."};
  }
  return {true, "VALID_VERIFIED", code, "Verified valid " + rule.name + " address and routing configuration."};
}

}  // namespace allswap
