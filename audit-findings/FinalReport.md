# Final Report: Coinbase Security Research Grant (private)

## Introduction

This report concludes my research grant focused on auditing Coinbase Solidity repositories for security vulnerabilities. The repositories under review were `coinbase/commerce-onchain-payment-protocol` and `coinbase/smart-wallet-permissions`. This document summarizes the findings, the impact of identified vulnerabilities, and recommendations for future improvements.

## Methodology

The audit process involved a detailed review of the smart contract codebases, focusing on:

- Code correctness and best practices
- Security vulnerabilities and potential exploits
- Documentation and readability

## Impact

The identified vulnerabilities ranged from informational notices to high-severity issues. The most significant issues include potential ownership hijacking and unauthorized access to sensitive functions via improper typecasting, which could lead to unauthorized control attacks and various unexpected behaviors.

## Overview

The smart contract repositories reviewed in this research demonstrated high code quality, robust security measures, and meticulous attention to detail. Both repositories introduce innovative onchain capabilities that significantly enhance existing functionalities and provide secure, efficient solutions to common blockchain interaction challenges.

### Repository: Smart Wallet Permissions

**Functionality Overview:**
The Smart Wallet Permissions repository allows users to grant permissions to applications, enabling them to submit transactions on their behalf. The design aligns with ERC-4337, leveraging existing infrastructure for bundlers and paymasters. Main functionalities include:

1. **ERC-4337 Alignment:** Utilizes the ERC-4337 standard for executing onchain transactions, benefiting from established solutions for DoS protection and gas payment modularization.
2. **Modular Permission System:** Introduces a Permission Manager that validates user operations, with modular permission checks delegated to specific Permission Contracts.
3. **Seamless Integration:** Optional addition to Coinbase Smart Wallet V1, facilitating easy adoption without requiring hard upgrades.

**Implications for Offchain Components:**
This system provides a secure and flexible way to manage permissions, automating transaction submission processes that were previously handled manually. It enhances user experience by reducing the complexity and risk associated with offchain transaction management.

### Repository: Coinbase Commerce Onchain Payment Protocol

**Functionality Overview:**
The Coinbase Commerce Onchain Payment Protocol allows merchants and payers to transact using the blockchain as a settlement layer. This protocol ensures guaranteed settlement, automatic conversion of tokens, and eliminates payment errors. Key functionalities include:

1. **Guaranteed Settlement:** Merchants always receive the exact amount requested, eliminating issues with underpayments or overpayments.
2. **Automatic Conversion:** Payers can use any token with liquidity on Uniswap, protecting merchants from price volatility.
3. **Error-Free Payments:** The protocol ensures that payments are always accurate and directed to the correct address.

**Implications for Offchain Components:**
This protocol automates and secures payment processes traditionally handled offchain, reducing the risk of human error and improving transaction efficiency. By leveraging blockchain technology, it offers a more transparent and reliable payment framework.

---

## Findings

Looking generally through the repositories in scope which were not as closely examined as the two main ones detailed in this report, many strengths were identified and should be commended- namely:

- Modern, battle-tested dependencies
- Recent updates and ongoing maintenance
- Gas efficiency (custom errors, struct and storage packing, etc)
- Adherence to best practices wrt documentation, naming conventions, and code style

Some room for improvement was also identified, though not strictly reported as findings as they are informational or incremental improvements. These include:

- ERC7201 Storage
  - Upgradeable proxy contracts can introduce storage collisions during updates and modern codebases make use of ERC7201 to eliminate this possibility. I have written a piece on the matter [here](https://mirror.xyz/%F0%9F%93%AF%F0%9F%93%AF%F0%9F%93%AF.eth/Tw2zF0xn3RHVtN0Ew1g9MWDwxm9xD7VYqxVIuOh_08Y)
    - Repositories like Coinbase Verifications make use of upgradeable proxy contracts but utilize 50 empty "gap" slots to avoid collisions which are cumbersome compared to ERC7201 and may not be enough for hefty upgrades
- Standardized directory structure
  - Modern tooling for smart contract repositories have pushed the envelope wrt standardizing directory structures. This advances portability and iterability across the industry, allowing developers to rely on predictable project structures when building, testing, and improving on the work of others. Foundry has established an opinionated approach for this, largely superceding older tooling like Hardhat and Truffle (now deprecated)
    - Repositories like Coinbase's Commerce Onchain Payment Protocol use a bare-bones structure neither recognizable by Foundry nor Hardhat, which introduces friction in portability
- ERC4337 v6
  - ERC4337 Account Abstraction is a notably complex onchain protocol with many moving parts and known issues do exist with previous releases such as v6. The newest version is v7 which has largely addressed those known issues
    - Repositories like Coinbase Smart Wallet, Magic Spend, and Smart Wallet Verifications all use the ERC4337 v6 Entrypoint contract and can be upgraded to v7

The following section provides a concise summary of more substantial identified issues, categorized by repository:

### Repository: https://github.com/coinbase/smart-wallet-permissions

**Report #2695390**
**Finding: Unsafe Typecast in `PermissionCallable::permissionedCall()`**
The `permissionedCall` function in the `PermissionCallable` contract contains an unsafe typecast of the `call` parameter. If the `call` parameter is shorter than 4 bytes, it gets zero-padded, potentially matching function selectors with trailing zero bytes. This allows attackers to bypass permission checks and trigger the fallback function, leading to unauthorized state changes or external calls. Adding a length check to ensure the `call` parameter is at least 4 bytes long is recommended to prevent this vulnerability.

### Repository: https://github.com/coinbase/smart-wallet-permissions

**Report #2709846**
**Finding: Ownership Hijacking through Nested Calls**
Smart wallets with enabled permissions can be hijacked if another smart contract account is an owner. Attackers can use nested calls to functions like `executeBatch()` to make unauthorized changes, such as upgrading the wallet's implementation or altering ownership. This vulnerability allows attackers to take full control of the affected wallet.

**Report #2731113**
**Finding: Incorrect Error Handling for Invalid Signatures**
In `PermissionManager::isValidSignature()`, invalid user operation signatures revert with the incorrect error `InvalidBeforeCallsCall()` instead of `InvalidCosigner()`. This misdirects developers and auditors during debugging. To resolve this, the function should throw the `InvalidCosigner` error immediately upon detecting an invalid signature.

**Report #2695182**
**Finding: Improper ECDSA Recovery Handling**
The `PermissionManager` improperly handles ECDSA signature recovery for cosignatures, allowing for malleable and compact ECDSA signatures. This does not generally lead to signature replay due to nonce management but could become a problem in case of future changes which rely on signature validity. The team has marked the issue as informational due to its limited practical impact.

### Repository: https://github.com/coinbase/commerce-onchain-payment-protocol

**Report #2682923**
**Finding: Mutable Prefix in `Transfers.sol::validIntent()`**
The `validIntent()` function in `Transfers.sol` uses a mutable prefix in its keccak256 hash computation, allowing attackers to manipulate the `TransferIntent` struct hash. While this theoretically weakens the cryptographic hardness of the hash, practical exploitation would require computational effort beyond current feasible capabilities. This finding has been de-escalated to informational/best practice due to the high computational cost of a successful attack.

**Informational Notice: Misconfigured Natspec Documentation**
All files within the `src` directory contain malformed Natspec Documentation, using `//` instead of `///`. This prevents the Solidity compiler from recognizing the comments, leading to issues with external tools like Etherscan that rely on valid Natspec documentation for displaying contract interfaces.

## Recommendations

Based on the findings, the following recommendations are proposed:

1. **Length Check for Call Data:** Add a length check in `PermissionCallable::permissionedCall()` to ensure the `call` parameter is at least 4 bytes long before typecasting and delegatecalling, to prevent unauthorized fallback function execution.
2. **Secure Ownership Logic:** Implement stricter checks to prevent unauthorized ownership changes via nested calls.
3. **Accurate Error Handling:** Ensure that error messages accurately reflect the underlying issue to aid in debugging and auditing.
4. **Malleability Protections:** Use libraries that guard against ECDSA signature malleability and compact signature replay to prevent DOS attacks.
5. **Correct Documentation:** Properly format Natspec documentation to ensure compatibility with Solidity compilers and external tools.
6. **Ensure Immutable Hashes:** Follow best practices for deterministic hashing to enhance cryptographic security.

## Conclusion

The audit has identified several areas for improvement in both repositories. Addressing these issues will enhance the security and robustness of the smart contracts, contributing to a more secure blockchain ecosystem. I appreciate the opportunity to contribute to this effort and look forward to any further collaboration in enhancing smart contract security.

---

Thank you for the opportunity to conduct this research.
