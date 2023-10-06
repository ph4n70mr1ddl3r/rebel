// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "ERC20.sol";
import "ERC20Burnable.sol";
import "MerkleProof.sol";
import "ERC20Votes.sol";
import "ERC20Permit.sol";


contract TestToken is ERC20, ERC20Burnable, ERC20Permit, ERC20Votes {
    bytes32 public immutable merkleRoot = 0xe72353e2f6010f96a36250acf32969ce9c708306426e834eb3931ff25b9310db;
    mapping(address => bool) public hasClaimed;

    struct Proof {
        uint32 rank;
        address to;
        uint16 term;
        bytes32[] proof;
    }

    error AlreadyClaimed();
    error NotInMerkle();

    event Claim(uint32 rank, address indexed to, uint16 term);

    constructor() ERC20("Test Token", "TEST") ERC20Permit("Test Token") {
    }

    function _afterTokenTransfer(address from, address to, uint256 amount) internal override(ERC20, ERC20Votes) {
        super._afterTokenTransfer(from, to, amount);
    }

    function _mint(address to, uint256 amount) internal override(ERC20, ERC20Votes) {
        super._mint(to, amount);
    }

    function _burn(address account, uint256 amount) internal override(ERC20, ERC20Votes) {
        super._burn(account, amount);
    }

    function claim(
        Proof calldata proof
    ) external {
        if (hasClaimed[proof.to]) revert AlreadyClaimed();

        bytes32 leaf = keccak256(
            bytes.concat(keccak256(abi.encode(proof.rank, proof.to, proof.term)))
        );
        bool isValidLeaf = MerkleProof.verify(proof.proof, merkleRoot, leaf);
        if (!isValidLeaf) revert NotInMerkle();

        hasClaimed[proof.to] = true;
 
        _mint(proof.to, proof.term * (10 ** uint256(decimals())));
        emit Claim(proof.rank, proof.to, proof.term);
    }
}