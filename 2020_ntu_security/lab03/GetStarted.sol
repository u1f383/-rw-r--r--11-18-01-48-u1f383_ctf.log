// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0;

contract Challenge {
    address player;

    constructor (address _player) {
        player = _player;
    }

    modifier onlyPlayer () {
        require(msg.sender == player);
        _;
    }
}

contract GetStartedFactory {
    event GetFlag(uint token);
    mapping(address => address) public instances;

    function create () public {
        instances[msg.sender] = address(new GetStarted(msg.sender));
    }

    function validate (uint token) public {
        GetStarted instance = GetStarted(instances[msg.sender]);
        require(instance.win());
        emit GetFlag(token);
    }
}

contract GetStarted is Challenge {
    bool public win = false;

    constructor (address _player) Challenge(_player) {}

    function callme () public onlyPlayer {
        win = true;
    }
}