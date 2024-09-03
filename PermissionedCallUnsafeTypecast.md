In the `PermissionCallable` abstract contract, the `permissionedCall` function contains an unsafe typecasting of the `bytes calldata call` parameter. This allows an attacker to exploit the function by providing a `call` parameter shorter than 4 bytes, which results in zero-padding. This zero-padding can inadvertently match function selectors that end in one or more zero bytes and are enabled to support permissioned calls. In such a case, intended security checks can by bypassed by an attacker, leading to unintended delegate calls and maliciously triggering the fallback function.

## Affected Code

```solidity
/// @inheritdoc IPermissionCallable
function permissionedCall(bytes calldata call) external payable returns (bytes memory res) {
    // check if call selector is allowed through permissionedCall
    if (!supportsPermissionedCallSelector(bytes4(call))) revert NotPermissionCallable(bytes4(call));
    // make self-delegatecall with provided call data
    return Address.functionDelegateCall(address(this), call);
}
```

## Vulnerability Explanation

In the provided code, the `call` parameter is unsafely typecast to a `bytes4` type without checking its length. If `call` is shorter than 4 bytes, the cast results in zero-padding. For instance, if `call` is `bytes('0x01')`, it is cast to `bytes4(0x01000000)`. This will bypass the `supportsPermissionedCallSelector` check if a function selector in the child contract ends in one or more zero bytes and supports permissioned calls.

Consider the following scenario:

1. A child contract inherits `PermissionCallable` and implements a function with a selector ending in one or more zero bytes, such as `0xff000000`.
2. The function is declared to support permissioned calls in the `supportsPermissionedCallSelector(selector)` function in the child contract, so `true` is returned for the `0xff000000` selector.
3. An attacker calls `permissionedCall(hex'ff')` on the child contract.
4. The cast to `bytes4` results in padding of the single `0xff` byte to `bytes4(0xff000000)`, which passes the `supportsPermissionedCallSelector` check and does not revert.
5. The self-delegatecall is executed with the non-padded value for `call = hex'ff'`, which triggers the fallback function as no Solidity function can bear a single-byte selector
6. The fallback function can thus be invoked at will by an attacker, leading to unintended state changes or other potential security issues such as unexpected external calls.

The likelihood of a random, innocently-implemented function bearing a selector with at least one trailing zero-byte is high enough to be relevant- somewhere in the low single digit percentages.

## Proof of concept:

```solidity
// vulnerable contract which enables permissioned calls for functions bearing selectors of at least one trailing zero-byte
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

    // foundry test case demonstrating vulnerability
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
```

## Recommended Mitigation

To prevent this vulnerability, add a length check to ensure the `call` data is at least 4 bytes long before proceeding with the typecast and delegatecall. For example, update the `permissionedCall` function as follows:

```solidity
function permissionedCall(bytes calldata call) external payable returns (bytes memory res) {
        // Ensure the call data is at least 4 bytes long to extract the function selector
        if (call.length < 4) revert InvalidSelector(call);
        // ... rest of function
}
```
