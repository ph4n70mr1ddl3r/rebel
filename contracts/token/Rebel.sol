// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "ERC20.sol";
import "ERC20Burnable.sol";
import "ERC20Permit.sol";
import "ERC20Votes.sol";
import "MerkleProof.sol";

contract Rebel is ERC20, ERC20Burnable, ERC20Permit, ERC20Votes {
    bytes32 public immutable merkleRoot = 0xe72353e2f6010f96a36250acf32969ce9c708306426e834eb3931ff25b9310db;
    mapping(address => bool) public hasClaimed;
    uint32 public counter = 4000000;

    struct Proof {
        uint32 rank;
        address to;
        uint16 term;
        bytes32[] proof;
    }

    error AlreadyClaimed();
    error NotInMerkle();

    constructor() ERC20("REBEL", "REBEL") ERC20Permit("REBEL") {}

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

    event Claim(uint32 rank, address indexed to, uint16 term);

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
 
        _mint(proof.to, proof.term * (10 ** uint256(decimals())) * counter / 1000000);
        counter = counter - 1;
        emit Claim(proof.rank, proof.to, proof.term);
    }
}