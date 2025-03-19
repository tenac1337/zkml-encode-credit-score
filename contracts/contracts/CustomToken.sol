// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract CustomToken is ERC20 {
    constructor(uint256 initialSupply) ERC20("CustomToken", "CT") {
        _mint(msg.sender, initialSupply);
    }
}
