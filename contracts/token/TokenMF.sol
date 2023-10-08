// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "ERC20.sol";
import "ERC20Burnable.sol";
import "ERC20Permit.sol";
import "ERC20Votes.sol";

contract TokenMF is ERC20, ERC20Burnable, ERC20Permit, ERC20Votes {
    constructor() ERC20("Token MF", "TMF") ERC20Permit("Token MF") {}

    // The following functions are overrides required by Solidity.

    function _update(address from, address to, uint256 value)
        internal
        override(ERC20, ERC20Votes)
    {
        super._update(from, to, value);
    }

    function nonces(address owner)
        public
        view
        override(ERC20Permit, Nonces)
        returns (uint256)
    {
        return super.nonces(owner);
    }
}