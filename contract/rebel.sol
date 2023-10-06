// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts@5.0.0/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts@5.0.0/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts@5.0.0/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts@5.0.0/token/ERC20/extensions/ERC20Votes.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract Rebel is ERC20, ERC20Burnable, ERC20Permit, ERC20Votes {

    bytes32 public immutable merkleRoot = 0xe72353e2f6010f96a36250acf32969ce9c708306426e834eb3931ff25b9310db;
    mapping(address => bool) public hasClaimed;
    uint32 bonus = 3200000;

    struct Proof {
        uint32 rank;
        address to;
        uint16 term;
        bytes32[] proof;
    }

    error AlreadyClaimed();
    error NotInMerkle();
    error NotYetTime();

    constructor() ERC20("Rebel DAO", "REBEL") ERC20Permit("Rebel DAO") {}

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

    event Claim(uint32 rank, address indexed to, uint16 term);

    function claim(Proof calldata proof) external {
        if (hasClaimed[proof.to]) revert AlreadyClaimed();
        if (block.number <= 110600000) revert NotYetTime();

        bytes32 leaf = keccak256(
            bytes.concat(
                keccak256(abi.encode(proof.rank, proof.to, proof.term))
            )
        );
        bool isValidLeaf = MerkleProof.verify(proof.proof, merkleRoot, leaf);
        if (!isValidLeaf) revert NotInMerkle();

        hasClaimed[proof.to] = true;

        _mint(
            proof.to,
            proof.term *
                (10 ** uint256(decimals())) +
                (proof.term * (10 ** uint256(decimals())) * bonus) /
                10000000
        );

        bonus = bonus - 1;

        emit Claim(proof.rank, proof.to, proof.term);
    }

}
