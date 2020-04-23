pragma solidity 0.6.6;

contract AA {
    int public i = 1;

    function set(int _i) public {
        i = _i;
    }
}