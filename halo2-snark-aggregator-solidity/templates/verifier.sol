// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.16 <0.9.0;

contract Verifier {
    function pairing(G1Point[] memory p1, G2Point[] memory p2)
        internal
        view
        returns (bool)
    {
        uint256 length = p1.length * 6;
        uint256[] memory input = new uint256[](length);
        uint256[1] memory result;
        bool ret;

        require(p1.length == p2.length);

        for (uint256 i = 0; i < length; i++) {
            input[0 + i * 6] = p1[i].x;
            input[1 + i * 6] = p1[i].y;
            input[2 + i * 6] = p2[i].x[0];
            input[3 + i * 6] = p2[i].x[1];
            input[4 + i * 6] = p2[i].y[0];
            input[5 + i * 6] = p2[i].y[1];
        }

        assembly {
            ret := staticcall(
                gas(),
                8,
                add(input, 0x20),
                mul(length, 0x20),
                result,
                0x20
            )
        }
        require(ret);
        return result[0] != 0;
    }

    uint256 constant q_mod =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function fr_from_bytes(bytes memory buf, uint256 offset)
        internal
        pure
        returns (uint256)
    {
        uint256 v;
        uint256 o;

        o = offset + 0x20;

        assembly {
            v := mload(add(buf, o))
        }

        return v;
    }

    function fr_add(uint256 a, uint256 b) internal pure returns (uint256 r) {
        return addmod(a, b, q_mod);
    }

    function fr_sub(uint256 a, uint256 b) internal pure returns (uint256 r) {
        return addmod(a, q_mod - b, q_mod);
    }

    function fr_mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, q_mod);
    }

    function fr_invert(uint256 a) internal view returns (uint256) {
        return fr_pow(a, q_mod - 2);
    }

    function fr_pow(uint256 a, uint256 power) internal view returns (uint256) {
        uint256[6] memory input;
        uint256[1] memory result;
        bool ret;

        input[0] = 32;
        input[1] = 32;
        input[2] = 32;
        input[3] = a;
        input[4] = power;
        input[5] = q_mod;

        assembly {
            ret := staticcall(gas(), 0x05, input, 0xc0, result, 0x20)
        }
        require(ret);

        return result[0];
    }

    function fr_div(uint256 a, uint256 b) internal view returns (uint256) {
        require(b != 0);
        return mulmod(a, fr_invert(b), q_mod);
    }

    function fr_mul_add_constant(
        uint256 a,
        uint256 b,
        uint256 c
    ) internal pure returns (uint256) {
        return fr_add(fr_mul(a, b), c);
    }

    function fr_reverse(uint256 input) internal pure returns (uint256 v) {
        v = input;

        // swap bytes
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8) |
            ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);

        // swap 2-byte long pairs
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16) |
            ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);

        // swap 4-byte long pairs
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32) |
            ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);

        // swap 8-byte long pairs
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64) |
            ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);

        // swap 16-byte long pairs
        v = (v >> 128) | (v << 128);
    }

    uint256 constant p_mod =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    struct G2Point {
        uint256[2] x;
        uint256[2] y;
    }

    function ecc_to_tuple(G1Point memory f)
        internal
        pure
        returns (uint256, uint256)
    {
        return (f.x, f.y);
    }

    function ecc_from(uint256 x, uint256 y)
        internal
        pure
        returns (G1Point memory r)
    {
        r.x = x;
        r.y = y;
    }

    function ecc_from_bytes(bytes memory buf, uint256 offset)
        internal
        pure
        returns (G1Point memory r)
    {
        uint256 x;
        uint256 y;
        uint256 o;

        o = offset + 0x20;

        assembly {
            x := mload(add(buf, o))
            y := mload(add(buf, add(o, 0x20)))
        }

        r.x = x;
        r.y = y;
    }

    function ecc_is_identity(G1Point memory a) internal pure returns (bool) {
        return a.x == 0 && a.y == 0;
    }

    function ecc_add(G1Point memory a, G1Point memory b)
        internal
        view
        returns (G1Point memory)
    {
        if (ecc_is_identity(a)) {
            return b;
        } else if (ecc_is_identity(b)) {
            return a;
        } else {
            bool ret = false;
            G1Point memory r;
            uint256[4] memory input_points;

            input_points[0] = a.x;
            input_points[1] = a.y;
            input_points[2] = b.x;
            input_points[3] = b.y;

            assembly {
                ret := staticcall(gas(), 6, input_points, 0x80, r, 0x40)
            }
            require(ret);

            return r;
        }
    }

    function ecc_sub(G1Point memory a, G1Point memory b)
        internal
        view
        returns (G1Point memory)
    {
        G1Point memory _b;
        _b.x = b.x;
        _b.y = p_mod - b.y;
        return ecc_add(a, _b);
    }

    function ecc_mul(G1Point memory p, uint256 s)
        internal
        view
        returns (G1Point memory)
    {
        if (ecc_is_identity(p)) {
            return p;
        } else {
            uint256[3] memory input;
            bool ret = false;
            G1Point memory r;

            input[0] = p.x;
            input[1] = p.y;
            input[2] = s;

            assembly {
                ret := staticcall(gas(), 7, input, 0x60, r, 0x40)
            }
            require(ret);

            return r;
        }
    }

    function toBytes(uint256 x) private pure returns (bytes32 v) {
        v = bytes32(x);
    }

    function update_hash_scalar(uint256 v, bytes memory absorbing, uint256 pos) internal pure {
        bytes32 tmp;

        // absorbing[pos] = 0x02
        assembly {
            mstore8(add(absorbing, add(pos, 32)), 0x02)
            pos := add(pos, 1)
        }

        tmp = toBytes(v);
        // to little-endian

        for (uint256 i = 0; i < 32; i++) {
            absorbing[pos] = tmp[31 - i];

            assembly {
                pos := add(pos, 1)
            }
        }
    }

    function update_hash_point(G1Point memory v, bytes memory absorbing, uint256 pos) internal pure {
        bytes32 tmp;
        //absorbing[pos] = 0x01;
        //pos++;
        assembly {
            mstore8(add(absorbing, add(pos, 32)), 0x01)
            pos := add(pos, 1)
        }

        tmp = toBytes(v.x);
        for (uint256 i = 0; i < 32; i++) {
            absorbing[pos] = tmp[31 - i];
            assembly {
                pos := add(pos, 1)
            }
        }

        tmp = toBytes(v.y);
        for (uint256 i = 0; i < 32; i++) {
            absorbing[pos] = tmp[31 - i];
            assembly {
                pos := add(pos, 1)
            }
        }
    }

    function to_scalar(bytes32 r) private pure returns (uint256 v) {
        uint256 tmp = uint256(r);
        tmp = fr_reverse(tmp);
        v = tmp % 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    }

    function squeeze_challenge(bytes memory absorbing, uint32 length) internal pure returns (uint256 v) {
        uint256 i;

        absorbing[length+1] = 0x00;
        length++;
        bytes memory tmp = new bytes(length);
        for (i = 0; i < length; i++) {
            tmp[i] = bytes1(absorbing[i]);
        }

        v = to_scalar(sha256(tmp));
    }

    function get_g2_s() internal pure returns (G2Point memory s) {
        s.x[0] = uint256({{s_g2_x0}});
        s.x[1] = uint256({{s_g2_x1}});
        s.y[0] = uint256({{s_g2_y0}});
        s.y[1] = uint256({{s_g2_y1}});
    }

    function get_g2_n() internal pure returns (G2Point memory n) {
        n.x[0] = uint256({{n_g2_x0}});
        n.x[1] = uint256({{n_g2_x1}});
        n.y[0] = uint256({{n_g2_y0}});
        n.y[1] = uint256({{n_g2_y1}});
    }

    function get_wx_wg(bytes memory proof, bytes memory instances)
        internal
        view
        returns (G1Point[2] memory)
    {
        uint256[{{memory_size}}] memory m;
        bytes memory absorbing = new bytes({{absorbing_length}});
        {% for statement in statements %}
        {{statement}}
        {%- endfor %}
        return [{{ wx }}, {{ wg }}];
    }

    function verify(bytes memory proof, bytes memory instances) public view {
        // wx, wg
        G1Point[2] memory wx_wg = get_wx_wg(proof, instances);
        G1Point[] memory g1_points = new G1Point[](2);
        g1_points[0] = wx_wg[0];
        g1_points[1] = wx_wg[1];
        G2Point[] memory g2_points = new G2Point[](2);
        g2_points[0] = get_g2_s();
        g2_points[1] = get_g2_s();

        bool checked = pairing(g1_points, g2_points);
        require(checked);
    }
}
