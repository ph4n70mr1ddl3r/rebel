// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "Governor.sol";
import "GovernorSettings.sol";
import "GovernorCountingSimple.sol";
import "GovernorVotes.sol";
import "GovernorVotesQuorumFraction.sol";

contract GovernMF is Governor, GovernorSettings, GovernorCountingSimple, GovernorVotes, GovernorVotesQuorumFraction {
    constructor(IVotes _token)
        Governor("GovernMF")
        GovernorSettings(7200 /* 1 day */, 50400 /* 1 week */, 1e18)
        GovernorVotes(_token)
        GovernorVotesQuorumFraction(4)
    {}

    // The following functions are overrides required by Solidity.

    function votingDelay()
        public
        view
        override(Governor, GovernorSettings)
        returns (uint256)
    {
        return super.votingDelay();
    }

    function votingPeriod()
        public
        view
        override(Governor, GovernorSettings)
        returns (uint256)
    {
        return super.votingPeriod();
    }

    function quorum(uint256 blockNumber)
        public
        view
        override(Governor, GovernorVotesQuorumFraction)
        returns (uint256)
    {
        return super.quorum(blockNumber);
    }

    function proposalThreshold()
        public
        view
        override(Governor, GovernorSettings)
        returns (uint256)
    {
        return super.proposalThreshold();
    }
}