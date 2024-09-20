CosignatureRecovery

Smart-wallet-permissions: Error handling for invalid user operation signatures reverts with incorrect 4-byte error selector.

In `PermissionManager::isValidSignature()`, user operation cosignatures which recover to a nonzero address that does not correspond to the `cosigner` revert with the error `InvalidBeforeCallsCall()` rather than the error which already exists for this mismatch: `InvalidCosigner(recoveredAddr)`.

In line 343 of `PermissionManager.sol` located [here](https://github.com/coinbase/smart-wallet-permissions/blob/a6cc481625cea81c6554b78e303e813e930d5e1c/src/PermissionManager.sol#L343), the `userOpCosigner` address is recovered using Solady's ECDSA library. As mentioned previously, this recovery does not guard against malleable or compact signatures and while that may be handled by the bundler's simulation step which will revert due to reused nonces in the ERC4337 Entrypoint contract, this recovery also does not check for whether the resulting recovered address actually matches the canonical `cosigner` immutable variable.

As a result, execution continues through other unrelated checks and logic constructing an abi-encoded array of `CoinbaseSmartWallet::Call` structs from the user operation data (which now contains the incorrect recovered `cosigner`) before reaching a strict bytes comparison of the constructed `Call` against the expected buffer called `beforeCallsData`. It is only at this strict bytes comparison where a revert is thrown: the `InvalidBeforeCallsCall()` error. The relevant code in the function is below:

```solidity
function isValidSignature(bytes32 userOpHash, bytes calldata userOpAuth) external view returns (bytes4 result) {
    (PermissionedUserOperation memory data) = abi.decode(userOpAuth, (PermissionedUserOperation));
    bytes32 permissionHash = hashPermission(data.permission);

    // ...start of function is unrelated

    // parse cosigner from cosignature
    address userOpCosigner = ECDSA.recover(userOpHash, data.userOpCosignature);

    // check userOp.callData is `executeBatch`
    if (bytes4(data.userOp.callData) != CoinbaseSmartWallet.executeBatch.selector) {
        revert CallErrors.SelectorNotAllowed(bytes4(data.userOp.callData));
    }

    CoinbaseSmartWallet.Call[] memory calls =
        abi.decode(BytesLib.trimSelector(data.userOp.callData), (CoinbaseSmartWallet.Call[]));

    // prepare beforeCalls data
    bytes memory beforeCallsData = abi.encodeWithSelector(
        PermissionManager.beforeCalls.selector,
        data.permission,
        address(bytes20(data.userOp.paymasterAndData)),
        userOpCosigner
    );

    // check first call is valid `self.beforeCalls`
    if (calls[0].target != address(this) || !BytesLib.eq(calls[0].data, beforeCallsData)) {
        revert InvalidBeforeCallsCall();
    }

    // ...rest of function
}
```

For developers working with the PermissionManager and auditors poking around the codebase, this error handling communicates somewhat of a red herring pointing at the `beforeCalls` call when in fact the signer of the userOp is incorrect. In a broad sense, the `beforeCalls` call is indeed wrong because it has been constructed with an incorrect argument, but throwing `InvalidCosigner` earlier in the function logic would be more specific and more useful to those trying to debug a malformed signature.

To resolve this point of confusion for developers and auditors, consider adding a separate if branch which throws `InvalidCosigner` as soon as it is discernably incorrect (after recovery) or add an optional parameter to the error blaming `beforeCalls` to provide information identifying the recovered address as the offending bytes like so: `error InvalidBeforeCallsCall(address zeroOrInvalidUserOpCosigner)`
