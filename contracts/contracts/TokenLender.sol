// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "./Verifier.sol";

contract TokenLender is Halo2Verifier {

    address public owner;

    error InvalidProof();

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can call this function");
        _;
    }

    function submitUnderwritingDecision(
        address user,
        bytes calldata proof,
        uint256[] calldata instances
    ) external onlyOwner {
        // Verify that the classification was valid using the proof.
        if (!verifyProof(proof, instances)) {
            revert InvalidProof();
        }

        // TODO: Tie to the user wallet address

        // Send funds to the user
        payable(user).transfer(100);
    }
}
