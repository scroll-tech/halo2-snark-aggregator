// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.16 <0.9.0;

library LibMulexp {
    function infinite() private pure returns (uint256[2] memory id) {
        // infinity is encodeds as (0, 0)
        // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-196.md]
        id[0] = 0;
        id[1] = 0;
    }

    function add(
        uint256 ax,
        uint256 ay,
        uint256 bx,
        uint256 by
    ) private view returns (uint256[2] memory r) {
        uint256[4] memory input;
        bool result = false;

        input[0] = ax;
        input[1] = ay;
        input[2] = bx;
        input[3] = by;

        assembly {
            result := staticcall(gas(), 6, input, 0x80, r, 0x40)
        }
        require(result);
    }

    function exp(uint256 scalar, uint256[2] memory base)
        private
        view
        returns (uint256[2] memory)
    {
        uint256[2] memory tmp;

        if (scalar == 0) {
            return infinite();
        } else if (scalar == 1) {
            return base;
        } else if (scalar % 2 == 1) {
            tmp = exp(scalar - 1, base);
            return add(base[0], base[1], tmp[0], tmp[1]);
        } else {
            tmp = add(base[0], base[1], base[0], base[1]);
            return exp(scalar / 2, tmp);
        }
    }

    function multiexp(uint256[] memory scalars, uint256[2][] memory bases)
        public
        view
        returns (uint256[2] memory)
    {
        require(bases.length >= scalars.length);

        uint256[2] memory acc = infinite();

        uint256 i;
        for (i = 0; i < scalars.length; i++) {
            uint256[2] memory tmp;
            tmp = exp(scalars[i], bases[i]);
            acc = add(acc[0], acc[1], tmp[0], tmp[1]);
        }

        return acc;
    }
}
