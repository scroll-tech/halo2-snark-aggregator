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

        for (uint256 i = 0; i < p1.length; i++) {
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

    function ecc_from(uint256 x, uint256 y)
        internal
        pure
        returns (G1Point memory r)
    {
        r.x = x;
        r.y = y;
    }

    function ecc_is_identity(uint256 x, uint256 y) internal pure returns (bool) {
        return x == 0 && y == 0;
    }

    function ecc_add(uint256 ax, uint256 ay, uint256 bx, uint256 by)
        internal
        view
        returns (uint256, uint256)
    {
        if (ecc_is_identity(ax, ay)) {
            return (bx, by);
        } else if (ecc_is_identity(bx, by)) {
            return (ax, ay);
        } else {
            bool ret = false;
            G1Point memory r;
            uint256[4] memory input_points;

            input_points[0] = ax;
            input_points[1] = ay;
            input_points[2] = bx;
            input_points[3] = by;

            assembly {
                ret := staticcall(gas(), 6, input_points, 0x80, r, 0x40)
            }
            require(ret);

            return (r.x, r.y);
        }
    }

    function ecc_sub(uint256 ax, uint256 ay, uint256 bx, uint256 by)
        internal
        view
        returns (uint256, uint256)
    {
        return ecc_add(ax, ay, bx, p_mod - by);
    }

    function ecc_mul(uint256 px, uint256 py, uint256 s)
        internal
        view
        returns (uint256, uint256)
    {
        if (ecc_is_identity(px, py)) {
            return (px, py);
        } else {
            uint256[3] memory input;
            bool ret = false;
            G1Point memory r;

            input[0] = px;
            input[1] = py;
            input[2] = s;

            assembly {
                ret := staticcall(gas(), 7, input, 0x60, r, 0x40)
            }
            require(ret);

            return (r.x, r.y);
        }
    }

    uint32 constant m_sep = 3 << 7;
    uint32 constant c_sep = 2 << 7;

    function convert_scalar(
        uint256[] memory m,
        uint256[] memory proof,
        uint256 v
    ) internal pure returns (uint256) {
        if (v >= m_sep) {
            return m[v - m_sep];
        } else if (v >= c_sep) {
            return v - c_sep;
        } else {
            return proof[v];
        }
    }

    function convert_point(
        uint256[] memory m,
        uint256[] memory proof,
        uint256 v
    ) internal pure returns (uint256, uint256) {
        if (v >= m_sep) {
            return (m[v - m_sep], m[v - m_sep + 1]);
        } else if (v >= c_sep) {
            revert();
        } else {
            return (proof[v], proof[v + 1]);
        }
    }

    function update(
        uint256[] memory m,
        uint256[] memory proof,
        uint256[] memory absorbing,
        uint256 opcodes
    ) internal view {
        uint32 i;
        uint256[4] memory buf;
        for (i = 0; i < 8; i++) {
            uint32 opcode = uint32(
                (opcodes >> ((7 - i) * 32)) & ((1 << 32) - 1)
            );
            if (opcode != 0) {
                uint32 t = (opcode >> 31);
                uint32 l =  (opcode >> 22) & 0x1ff;
                uint32 op = (opcode >> 18) & 0xf;
                uint32 r0 = (opcode >> 9) & 0x1ff;
                uint32 r1 = opcode & 0x1ff;

                if (op == 5) {
                    l = l - m_sep;
                    m[l] = squeeze_challenge(absorbing, uint32(r0));
                    continue;
                }

                if (op == 6) {
                    update_hash_scalar(
                        convert_scalar(m, proof, r0),
                        absorbing,
                        r1
                    );
                    continue;
                }

                if (t == 0) {
                    l = l - m_sep;
                    buf[0] = convert_scalar(m, proof, r0);
                    buf[1] = convert_scalar(m, proof, r1);
                    if (op == 1) {
                        m[l] = fr_add(buf[0], buf[1]);
                    } else if (op == 2) {
                        m[l] = fr_sub(buf[0], buf[1]);
                    } else if (op == 3) {
                        m[l] = fr_mul(buf[0], buf[1]);
                    } else if (op == 4) {
                        m[l] = fr_div(buf[0], buf[1]);
                    } else {
                        revert();
                    }
                } else {
                    l = l - m_sep;
                    (buf[0], buf[1]) = convert_point(m, proof, r0);
                    if (op == 1) {
                        (buf[2], buf[3]) = convert_point(m, proof, r1);
                        (m[l], m[l + 1]) = ecc_add(buf[0], buf[1], buf[2], buf[3]);
                    } else if (op == 2) {
                        (buf[2], buf[3]) = convert_point(m, proof, r1);
                        (m[l], m[l + 1]) = ecc_sub(buf[0], buf[1], buf[2], buf[3]);
                    } else if (op == 3) {
                        buf[2] = convert_scalar(m, proof, r1);
                        (m[l], m[l + 1]) = ecc_mul(buf[0], buf[1], buf[2]);
                    } else {
                        revert();
                    }
                }
            }
        }
    }

    function update_hash_scalar(uint256 v, uint256[] memory absorbing, uint256 pos) internal pure {
        absorbing[pos++] = 0x02;
        absorbing[pos++] = v;
    }

    function update_hash_point(uint256 x, uint256 y, uint256[] memory absorbing, uint256 pos) internal pure {
        absorbing[pos++] = 0x01;
        absorbing[pos++] = x;
        absorbing[pos++] = y;
    }

    function to_scalar(bytes32 r) private pure returns (uint256 v) {
        uint256 tmp = uint256(r);
        tmp = fr_reverse(tmp);
        v = tmp % 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    }

    function hash(uint256[] memory data, uint256 length) private pure returns (bytes32 v) {
        uint256[] memory buf = new uint256[](length);
        uint256 i = 0;

        for (i = 0; i < length; i++) {
            buf[i] = data[i];
        }

        v = sha256(abi.encodePacked(buf, uint8(0)));
    }

    function squeeze_challenge(uint256[] memory absorbing, uint32 length) internal pure returns (uint256 v) {
        bytes32 res = hash(absorbing, length);
        v = to_scalar(res);
        absorbing[0] = uint256(res);
        length = 1;
    }

    function get_g2_s() internal pure returns (G2Point memory s) {
        s.x[0] = uint256(19996377281670978687180986182441301914718493784645870391946826878753710639456);
        s.x[1] = uint256(4287478848095488335912479212753150961411468232106701703291869721868407715111);
        s.y[0] = uint256(6995741485533723263267942814565501722132921805029874890336635619836737653877);
        s.y[1] = uint256(11126659726611658836425410744462014686753643655648740844565393330984713428953);
    }

    function get_g2_n() internal pure returns (G2Point memory n) {
        n.x[0] = uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634);
        n.x[1] = uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781);
        n.y[0] = uint256(17805874995975841540914202342111839520379459829704422454583296818431106115052);
        n.y[1] = uint256(13392588948715843804641432497768002650278120570034223513918757245338268106653);
    }

    function get_wx_wg(uint256[] memory proof, uint256[] memory instances)
        internal
        view
        returns (G1Point[2] memory)
    {
        uint256[] memory m = new uint256[](76);
        uint256[] memory absorbing = new uint256[](143);
        
        update_hash_scalar(1369124729547139816537867930164544665665084315090393387426763107646797459004, absorbing, 0);
        update_hash_point(instances[0], instances[1], absorbing, 2);
        update_hash_point(proof[0], proof[1], absorbing, 5);
        update_hash_point(proof[2], proof[3], absorbing, 8);
        update_hash_point(proof[4], proof[5], absorbing, 11);
        update_hash_point(proof[6], proof[7], absorbing, 14);
        update_hash_point(proof[8], proof[9], absorbing, 17);
        // m[0] = (squeeze_challenge(absorbing, 20));
        update(m, proof, absorbing, uint256(1611933696));
        update_hash_point(proof[10], proof[11], absorbing, 1);
        update_hash_point(proof[12], proof[13], absorbing, 4);
        update_hash_point(proof[14], proof[15], absorbing, 7);
        update_hash_point(proof[16], proof[17], absorbing, 10);
        update_hash_point(proof[18], proof[19], absorbing, 13);
        update_hash_point(proof[20], proof[21], absorbing, 16);
        update_hash_point(proof[22], proof[23], absorbing, 19);
        update_hash_point(proof[24], proof[25], absorbing, 22);
        update_hash_point(proof[26], proof[27], absorbing, 25);
        update_hash_point(proof[28], proof[29], absorbing, 28);
        update_hash_point(proof[30], proof[31], absorbing, 31);
        update_hash_point(proof[32], proof[33], absorbing, 34);
        update_hash_point(proof[34], proof[35], absorbing, 37);
        update_hash_point(proof[36], proof[37], absorbing, 40);
        // m[1] = (squeeze_challenge(absorbing, 43));
        // m[2] = (squeeze_challenge(absorbing, 1));
        update(m, proof, absorbing, uint256(6941267485305078272));
        update_hash_point(proof[38], proof[39], absorbing, 1);
        update_hash_point(proof[40], proof[41], absorbing, 4);
        update_hash_point(proof[42], proof[43], absorbing, 7);
        update_hash_point(proof[44], proof[45], absorbing, 10);
        update_hash_point(proof[46], proof[47], absorbing, 13);
        update_hash_point(proof[48], proof[49], absorbing, 16);
        update_hash_point(proof[50], proof[51], absorbing, 19);
        update_hash_point(proof[52], proof[53], absorbing, 22);
        update_hash_point(proof[54], proof[55], absorbing, 25);
        update_hash_point(proof[56], proof[57], absorbing, 28);
        // m[3] = (squeeze_challenge(absorbing, 31));
        update(m, proof, absorbing, uint256(1624522240));
        update_hash_point(proof[58], proof[59], absorbing, 1);
        update_hash_point(proof[60], proof[61], absorbing, 4);
        update_hash_point(proof[62], proof[63], absorbing, 7);
        update_hash_point(proof[64], proof[65], absorbing, 10);
        // m[5] = (squeeze_challenge(absorbing, 13));
        update(m, proof, absorbing, uint256(1632901632));
        m[4] = (fr_mul(13446667982376394161563610564587413125564757801019538732601045199901075958935, m[5]));
        m[6] = (fr_mul(16569469942529664681363945218228869388192121720036659574609237682362097667612, m[5]));
        m[7] = (fr_mul(14803907026430593724305438564799066516271154714737734572920456128449769927233, m[5]));
        // m[8] = (fr_mul(m[5], m[5]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        update(m, proof, absorbing, uint256(44353241382341306652411815151080732042004624151446948348494836021365337690504));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        update(m, proof, absorbing, uint256(44353282873699227397246459143616950965216230879012214638435884439821511233928));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        update(m, proof, absorbing, uint256(44353282873699227397246459143616950965216230879012214638435884439821511233928));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // update_hash_scalar(proof[66], absorbing, 1);
        // update_hash_scalar(proof[67], absorbing, 3);
        // update_hash_scalar(proof[68], absorbing, 5);
        // update_hash_scalar(proof[69], absorbing, 7);
        // update_hash_scalar(proof[70], absorbing, 9);
        // update_hash_scalar(proof[71], absorbing, 11);
        update(m, proof, absorbing, uint256(44353282873699227394844410993027186037818921777607132895392824891710954311179));
        // update_hash_scalar(proof[72], absorbing, 13);
        // update_hash_scalar(proof[73], absorbing, 15);
        // update_hash_scalar(proof[74], absorbing, 17);
        // update_hash_scalar(proof[75], absorbing, 19);
        // update_hash_scalar(proof[76], absorbing, 21);
        // update_hash_scalar(proof[77], absorbing, 23);
        // update_hash_scalar(proof[78], absorbing, 25);
        // update_hash_scalar(proof[79], absorbing, 27);
        update(m, proof, absorbing, uint256(43398531518033472510976296697974618753677792803965758768335704256148971035));
        // update_hash_scalar(proof[80], absorbing, 29);
        // update_hash_scalar(proof[81], absorbing, 31);
        // update_hash_scalar(proof[82], absorbing, 33);
        // update_hash_scalar(proof[83], absorbing, 35);
        // update_hash_scalar(proof[84], absorbing, 37);
        // update_hash_scalar(proof[85], absorbing, 39);
        // update_hash_scalar(proof[86], absorbing, 41);
        // update_hash_scalar(proof[87], absorbing, 43);
        update(m, proof, absorbing, uint256(43509390818754607384153887190047440155008776903332483748096056444218551851));
        // update_hash_scalar(proof[88], absorbing, 45);
        // update_hash_scalar(proof[89], absorbing, 47);
        // update_hash_scalar(proof[90], absorbing, 49);
        // update_hash_scalar(proof[91], absorbing, 51);
        // update_hash_scalar(proof[92], absorbing, 53);
        // update_hash_scalar(proof[93], absorbing, 55);
        // update_hash_scalar(proof[94], absorbing, 57);
        // update_hash_scalar(proof[95], absorbing, 59);
        update(m, proof, absorbing, uint256(43620250119475742257331477682120261556339761002699208727856408632288132667));
        // update_hash_scalar(proof[96], absorbing, 61);
        // update_hash_scalar(proof[97], absorbing, 63);
        // update_hash_scalar(proof[98], absorbing, 65);
        // update_hash_scalar(proof[99], absorbing, 67);
        // update_hash_scalar(proof[100], absorbing, 69);
        // update_hash_scalar(proof[101], absorbing, 71);
        // update_hash_scalar(proof[102], absorbing, 73);
        // update_hash_scalar(proof[103], absorbing, 75);
        update(m, proof, absorbing, uint256(43731109420196877130509068174193082957670745102065933707616760820357713483));
        // update_hash_scalar(proof[104], absorbing, 77);
        // update_hash_scalar(proof[105], absorbing, 79);
        // update_hash_scalar(proof[106], absorbing, 81);
        // update_hash_scalar(proof[107], absorbing, 83);
        // update_hash_scalar(proof[108], absorbing, 85);
        // update_hash_scalar(proof[109], absorbing, 87);
        // update_hash_scalar(proof[110], absorbing, 89);
        // update_hash_scalar(proof[111], absorbing, 91);
        update(m, proof, absorbing, uint256(43841968720918012003686658666265904359001729201432658687377113008427294299));
        // update_hash_scalar(proof[112], absorbing, 93);
        // update_hash_scalar(proof[113], absorbing, 95);
        // update_hash_scalar(proof[114], absorbing, 97);
        // update_hash_scalar(proof[115], absorbing, 99);
        // update_hash_scalar(proof[116], absorbing, 101);
        // update_hash_scalar(proof[117], absorbing, 103);
        // update_hash_scalar(proof[118], absorbing, 105);
        // update_hash_scalar(proof[119], absorbing, 107);
        update(m, proof, absorbing, uint256(43952828021639146876864249158338725760332713300799383667137465196496875115));
        // update_hash_scalar(proof[120], absorbing, 109);
        // update_hash_scalar(proof[121], absorbing, 111);
        // update_hash_scalar(proof[122], absorbing, 113);
        // update_hash_scalar(proof[123], absorbing, 115);
        // update_hash_scalar(proof[124], absorbing, 117);
        // update_hash_scalar(proof[125], absorbing, 119);
        // update_hash_scalar(proof[126], absorbing, 121);
        // update_hash_scalar(proof[127], absorbing, 123);
        update(m, proof, absorbing, uint256(44063687322360281750041839650411547161663697400166108646897817384566455931));
        // update_hash_scalar(proof[128], absorbing, 125);
        // update_hash_scalar(proof[129], absorbing, 127);
        // update_hash_scalar(proof[130], absorbing, 129);
        // update_hash_scalar(proof[131], absorbing, 131);
        // update_hash_scalar(proof[132], absorbing, 133);
        // update_hash_scalar(proof[133], absorbing, 135);
        // update_hash_scalar(proof[134], absorbing, 137);
        // update_hash_scalar(proof[135], absorbing, 139);
        update(m, proof, absorbing, uint256(44174546623081416623219430142484368562994681499532833626658169572636036747));
        // update_hash_scalar(proof[136], absorbing, 141);
        // m[9] = (squeeze_challenge(absorbing, 143));
        // m[11] = (squeeze_challenge(absorbing, 1));
        update(m, proof, absorbing, uint256(30301311430608612482089472));
        update_hash_point(proof[137], proof[138], absorbing, 1);
        update_hash_point(proof[139], proof[140], absorbing, 4);
        update_hash_point(proof[141], proof[142], absorbing, 7);
        update_hash_point(proof[143], proof[144], absorbing, 10);
        // m[10] = (fr_sub(m[8], 1));
        // m[13] = (fr_sub(m[5], 1));
        update(m, proof, absorbing, uint256(7100787935138220801));
        m[13] = (fr_mul(m[13], 67108864));
        // m[13] = (fr_div(m[10], m[13]));
        update(m, proof, absorbing, uint256(1666389389));
        m[12] = (fr_mul(m[10], 14803907026430593724305438564799066516271154714737734572920456128449769927233));
        m[15] = (fr_sub(m[5], 14803907026430593724305438564799066516271154714737734572920456128449769927233));
        m[15] = (fr_mul(m[15], 67108864));
        // m[12] = (fr_div(m[12], m[15]));
        update(m, proof, absorbing, uint256(1662196111));
        m[15] = (fr_mul(m[10], 11377606117859914088982205826922132024839443553408109299929510653283289974216));
        m[14] = (fr_sub(m[5], 11377606117859914088982205826922132024839443553408109299929510653283289974216));
        m[14] = (fr_mul(m[14], 67108864));
        // m[15] = (fr_div(m[15], m[14]));
        update(m, proof, absorbing, uint256(1674780558));
        m[14] = (fr_mul(m[10], 3693565015985198455139889557180396682968596245011005461846595820698933079918));
        m[16] = (fr_sub(m[5], 3693565015985198455139889557180396682968596245011005461846595820698933079918));
        m[16] = (fr_mul(m[16], 67108864));
        // m[16] = (fr_div(m[14], m[16]));
        update(m, proof, absorbing, uint256(1678974352));
        m[17] = (fr_mul(m[10], 17329448237240114492580865744088056414251735686965494637158808787419781175510));
        m[14] = (fr_sub(m[5], 17329448237240114492580865744088056414251735686965494637158808787419781175510));
        m[14] = (fr_mul(m[14], 67108864));
        // m[17] = (fr_div(m[17], m[14]));
        update(m, proof, absorbing, uint256(1683170190));
        m[14] = (fr_mul(m[10], 6047398202650739717314770882059679662647667807426525133977681644606291529311));
        m[18] = (fr_sub(m[5], 6047398202650739717314770882059679662647667807426525133977681644606291529311));
        m[18] = (fr_mul(m[18], 67108864));
        // m[18] = (fr_div(m[14], m[18]));
        update(m, proof, absorbing, uint256(1687362962));
        m[19] = (fr_mul(m[10], 16569469942529664681363945218228869388192121720036659574609237682362097667612));
        m[14] = (fr_sub(m[5], 16569469942529664681363945218228869388192121720036659574609237682362097667612));
        m[14] = (fr_mul(m[14], 67108864));
        // m[19] = (fr_div(m[19], m[14]));
        // m[12] = (fr_add(m[12], m[15]));
        // m[16] = (fr_add(m[12], m[16]));
        // m[16] = (fr_add(m[16], m[17]));
        // m[16] = (fr_add(m[16], m[18]));
        // m[15] = (fr_mul(proof[74], proof[72]));
        // m[15] = (fr_add(proof[73], m[15]));
        // m[12] = (fr_mul(proof[75], proof[67]));
        update(m, proof, absorbing, uint256(45604362595843667079944853715412458486782128512858874607800826216125081359939));
        // m[15] = (fr_add(m[15], m[12]));
        // m[12] = (fr_mul(proof[76], proof[68]));
        // m[15] = (fr_add(m[15], m[12]));
        // m[12] = (fr_mul(proof[77], proof[69]));
        // m[15] = (fr_add(m[15], m[12]));
        // m[12] = (fr_mul(proof[78], proof[70]));
        // m[15] = (fr_add(m[15], m[12]));
        // m[12] = (fr_mul(proof[79], proof[71]));
        update(m, proof, absorbing, uint256(45130792314594652911844465420000516050467010770044101601013809863450042342983));
        // m[15] = (fr_add(m[15], m[12]));
        // m[12] = (fr_mul(proof[68], proof[67]));
        // m[12] = (fr_mul(proof[80], m[12]));
        // m[15] = (fr_add(m[15], m[12]));
        // m[12] = (fr_mul(proof[70], proof[69]));
        // m[12] = (fr_mul(proof[81], m[12]));
        // m[15] = (fr_add(m[15], m[12]));
        // m[12] = (fr_sub(1, proof[97]));
        update(m, proof, absorbing, uint256(45130792314594627194540793137914206460354833443034870220556458093527261905505));
        // m[12] = (fr_mul(m[12], m[13]));
        // m[18] = (fr_mul(proof[100], proof[100]));
        // m[18] = (fr_sub(m[18], proof[100]));
        // m[18] = (fr_mul(m[18], m[19]));
        // m[17] = (fr_sub(proof[100], proof[99]));
        // m[17] = (fr_mul(m[13], m[17]));
        // m[14] = (fr_mul(m[5], m[1]));
        // m[21] = (fr_mul(proof[91], m[1]));
        update(m, proof, absorbing, uint256(44805651071315341890384044492595805618504452776396798032918835214727414331265));
        // m[21] = (fr_add(m[21], m[2]));
        // m[21] = (fr_add(proof[67], m[21]));
        // m[21] = (fr_mul(proof[98], m[21]));
        // m[20] = (fr_add(m[14], m[2]));
        // m[20] = (fr_add(proof[67], m[20]));
        // m[20] = (fr_mul(proof[97], m[20]));
        update(m, proof, absorbing, uint256(2483329521785241698034788896230326114354038605976366269332));
        m[23] = (fr_mul(m[14], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[22] = (fr_mul(proof[92], m[1]));
        // m[22] = (fr_add(m[22], m[2]));
        // m[22] = (fr_add(proof[68], m[22]));
        // m[21] = (fr_mul(m[21], m[22]));
        // m[22] = (fr_add(m[23], m[2]));
        // m[22] = (fr_add(proof[68], m[22]));
        // m[20] = (fr_mul(m[20], m[22]));
        update(m, proof, absorbing, uint256(10694432213804290098286909504392228689180166052163828454772072982934));
        m[23] = (fr_mul(m[23], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[22] = (fr_mul(proof[93], m[1]));
        // m[22] = (fr_add(m[22], m[2]));
        // m[22] = (fr_add(proof[69], m[22]));
        // m[21] = (fr_mul(m[21], m[22]));
        // m[22] = (fr_add(m[23], m[2]));
        // m[22] = (fr_add(proof[69], m[22]));
        // m[20] = (fr_mul(m[20], m[22]));
        update(m, proof, absorbing, uint256(10694435427680378616267460762540985235025864389817615027622091106710));
        m[23] = (fr_mul(m[23], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[20] = (fr_sub(m[21], m[20]));
        // m[16] = (fr_add(m[19], m[16]));
        // m[16] = (fr_sub(1, m[16]));
        // m[20] = (fr_mul(m[16], m[20]));
        update(m, proof, absorbing, uint256(134310026740058545698852908003551551892));
        m[14] = (fr_mul(11166246659983828508719468090013646171463329086121580628794302409516816350802, m[14]));
        // m[21] = (fr_mul(proof[94], m[1]));
        // m[21] = (fr_add(m[21], m[2]));
        // m[21] = (fr_add(proof[70], m[21]));
        // m[21] = (fr_mul(proof[101], m[21]));
        // m[23] = (fr_add(m[14], m[2]));
        // m[23] = (fr_add(proof[70], m[23]));
        // m[23] = (fr_mul(proof[100], m[23]));
        update(m, proof, absorbing, uint256(10668110568633197107119803396880096005810416720237053761258242492823));
        m[14] = (fr_mul(m[14], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[22] = (fr_mul(proof[95], m[1]));
        // m[22] = (fr_add(m[22], m[2]));
        // m[22] = (fr_add(proof[71], m[22]));
        // m[21] = (fr_mul(m[21], m[22]));
        // m[22] = (fr_add(m[14], m[2]));
        // m[22] = (fr_add(proof[71], m[22]));
        // m[23] = (fr_mul(m[23], m[22]));
        update(m, proof, absorbing, uint256(10694441855432555652228563278838498326717260980122591481668526092182));
        m[14] = (fr_mul(m[14], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[22] = (fr_mul(proof[96], m[1]));
        // m[22] = (fr_add(m[22], m[2]));
        // m[22] = (fr_add(proof[66], m[22]));
        // m[21] = (fr_mul(m[21], m[22]));
        // m[22] = (fr_add(m[14], m[2]));
        // m[22] = (fr_add(proof[66], m[22]));
        // m[23] = (fr_mul(m[23], m[22]));
        update(m, proof, absorbing, uint256(10694445069308644170209113491639823691439999558289584010932459089814));
        m[14] = (fr_mul(m[14], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[14] = (fr_sub(m[21], m[23]));
        // m[14] = (fr_mul(m[16], m[14]));
        // m[21] = (fr_add(proof[104], m[1]));
        // m[21] = (fr_mul(m[21], proof[103]));
        // m[23] = (fr_add(proof[106], m[2]));
        // m[21] = (fr_mul(m[23], m[21]));
        // m[23] = (fr_mul(proof[82], proof[67]));
        // m[0] = (fr_mul(m[0], 0));
        update(m, proof, absorbing, uint256(45024864608277224190659044756725479740976985170128751636520663166222655750400));
        // m[23] = (fr_add(m[0], m[23]));
        // m[22] = (fr_add(m[0], proof[83]));
        // m[24] = (fr_sub(1, proof[102]));
        // m[24] = (fr_mul(m[24], m[13]));
        // m[25] = (fr_mul(proof[102], proof[102]));
        // m[25] = (fr_sub(m[25], proof[102]));
        // m[25] = (fr_mul(m[25], m[19]));
        // m[23] = (fr_add(m[23], m[1]));
        update(m, proof, absorbing, uint256(46035211256191174998438514839189669756178825564442790163984439931253182377857));
        // m[23] = (fr_mul(m[23], proof[102]));
        // m[22] = (fr_add(m[22], m[2]));
        // m[23] = (fr_mul(m[22], m[23]));
        // m[21] = (fr_sub(m[21], m[23]));
        // m[21] = (fr_mul(m[16], m[21]));
        // m[23] = (fr_sub(proof[104], proof[106]));
        // m[26] = (fr_mul(m[23], m[13]));
        // m[27] = (fr_sub(proof[104], proof[105]));
        update(m, proof, absorbing, uint256(46049655290257693565294404144774361132362410104697957946707536770860424155241));
        // m[27] = (fr_mul(m[27], m[23]));
        // m[27] = (fr_mul(m[16], m[27]));
        // m[23] = (fr_add(proof[109], m[1]));
        // m[23] = (fr_mul(m[23], proof[108]));
        // m[28] = (fr_add(proof[111], m[2]));
        // m[28] = (fr_mul(m[28], m[23]));
        // m[29] = (fr_mul(proof[82], proof[68]));
        // m[29] = (fr_add(m[0], m[29]));
        update(m, proof, absorbing, uint256(46502031575730380006493527806985963987867349124838046129821931315537440604573));
        // m[23] = (fr_sub(1, proof[107]));
        // m[23] = (fr_mul(m[23], m[13]));
        // m[30] = (fr_mul(proof[107], proof[107]));
        // m[30] = (fr_sub(m[30], proof[107]));
        // m[30] = (fr_mul(m[30], m[19]));
        // m[31] = (fr_add(m[29], m[1]));
        // m[31] = (fr_mul(m[31], proof[107]));
        // m[31] = (fr_mul(m[22], m[31]));
        update(m, proof, absorbing, uint256(46040517512923898559591714515684555387836416806327410176406884961248875589023));
        // m[28] = (fr_sub(m[28], m[31]));
        // m[28] = (fr_mul(m[16], m[28]));
        // m[31] = (fr_sub(proof[109], proof[111]));
        // m[29] = (fr_mul(m[31], m[13]));
        // m[33] = (fr_sub(proof[109], proof[110]));
        // m[33] = (fr_mul(m[33], m[31]));
        // m[33] = (fr_mul(m[16], m[33]));
        // m[31] = (fr_add(proof[114], m[1]));
        update(m, proof, absorbing, uint256(46608056418815678063844882496689585885092409493856479407225511324064699180417));
        // m[31] = (fr_mul(m[31], proof[113]));
        // m[32] = (fr_add(proof[116], m[2]));
        // m[31] = (fr_mul(m[32], m[31]));
        // m[32] = (fr_mul(proof[82], proof[69]));
        // m[32] = (fr_add(m[0], m[32]));
        // m[34] = (fr_sub(1, proof[112]));
        // m[34] = (fr_mul(m[34], m[13]));
        // m[35] = (fr_mul(proof[112], proof[112]));
        update(m, proof, absorbing, uint256(46954391712187537034873459266874515747674529282739293309779309769713769046128));
        // m[35] = (fr_sub(m[35], proof[112]));
        // m[35] = (fr_mul(m[35], m[19]));
        // m[32] = (fr_add(m[32], m[1]));
        // m[32] = (fr_mul(m[32], proof[112]));
        // m[32] = (fr_mul(m[22], m[32]));
        // m[31] = (fr_sub(m[31], m[32]));
        // m[31] = (fr_mul(m[16], m[31]));
        // m[32] = (fr_sub(proof[114], proof[116]));
        update(m, proof, absorbing, uint256(47399692359605766682325084362777953912927643917033431747570653673040990758004));
        // m[36] = (fr_mul(m[32], m[13]));
        // m[37] = (fr_sub(proof[114], proof[115]));
        // m[32] = (fr_mul(m[37], m[32]));
        // m[32] = (fr_mul(m[16], m[32]));
        // m[37] = (fr_add(proof[119], m[1]));
        // m[37] = (fr_mul(m[37], proof[118]));
        // m[39] = (fr_add(proof[121], m[2]));
        // m[39] = (fr_mul(m[39], m[37]));
        update(m, proof, absorbing, uint256(47519804233167444812551795110788434558174474293571823038987527866958406963109));
        // m[38] = (fr_mul(proof[82], proof[70]));
        // m[38] = (fr_add(m[0], m[38]));
        // m[37] = (fr_sub(1, proof[117]));
        // m[37] = (fr_mul(m[37], m[13]));
        // m[40] = (fr_mul(proof[117], proof[117]));
        // m[40] = (fr_sub(m[40], proof[117]));
        // m[40] = (fr_mul(m[40], m[19]));
        // m[38] = (fr_add(m[38], m[1]));
        update(m, proof, absorbing, uint256(47741341475022413993873332257526473547106083425089347236733515786658800684417));
        // m[38] = (fr_mul(m[38], proof[117]));
        // m[22] = (fr_mul(m[22], m[38]));
        // m[39] = (fr_sub(m[39], m[22]));
        // m[39] = (fr_mul(m[16], m[39]));
        // m[38] = (fr_sub(proof[119], proof[121]));
        // m[22] = (fr_mul(m[38], m[13]));
        // m[41] = (fr_sub(proof[119], proof[120]));
        // m[38] = (fr_mul(m[41], m[38]));
        update(m, proof, absorbing, uint256(47746035929237837481055603904378203861413580951724522447494232992378757534630));
        // m[38] = (fr_mul(m[16], m[38]));
        // m[41] = (fr_add(proof[124], m[1]));
        // m[41] = (fr_mul(m[41], proof[123]));
        // m[43] = (fr_add(proof[126], m[2]));
        // m[41] = (fr_mul(m[43], m[41]));
        // m[43] = (fr_mul(proof[84], proof[67]));
        // m[43] = (fr_add(m[0], m[43]));
        // m[42] = (fr_add(m[0], proof[85]));
        update(m, proof, absorbing, uint256(47745740475678348008208016264658411657836705714361340270001471191488183861333));
        // m[44] = (fr_sub(1, proof[122]));
        // m[44] = (fr_mul(m[44], m[13]));
        // m[45] = (fr_mul(proof[122], proof[122]));
        // m[45] = (fr_sub(m[45], proof[122]));
        // m[45] = (fr_mul(m[45], m[19]));
        // m[43] = (fr_add(m[43], m[1]));
        // m[43] = (fr_mul(m[43], proof[122]));
        // m[42] = (fr_add(m[42], m[2]));
        update(m, proof, absorbing, uint256(48415160372938204128561008363172370512818007834067480651963283587643281462658));
        // m[42] = (fr_mul(m[42], m[43]));
        // m[41] = (fr_sub(m[41], m[42]));
        // m[41] = (fr_mul(m[16], m[41]));
        // m[42] = (fr_sub(proof[124], proof[126]));
        // m[43] = (fr_mul(m[42], m[13]));
        // m[47] = (fr_sub(proof[124], proof[125]));
        // m[47] = (fr_mul(m[47], m[42]));
        // m[47] = (fr_mul(m[16], m[47]));
        update(m, proof, absorbing, uint256(48198412349873993980272604008681653342681257397408269068573819464205609148847));
        // m[46] = (fr_add(proof[129], m[1]));
        // m[46] = (fr_mul(m[46], proof[128]));
        // m[42] = (fr_add(proof[131], m[2]));
        // m[46] = (fr_mul(m[42], m[46]));
        // m[42] = (fr_mul(proof[86], proof[67]));
        // m[42] = (fr_add(m[0], m[42]));
        // m[48] = (fr_add(m[0], proof[87]));
        // m[49] = (fr_sub(1, proof[127]));
        update(m, proof, absorbing, uint256(48632489652424579746744959689658322584525786050523506868352623748581580997247));
        // m[49] = (fr_mul(m[49], m[13]));
        // m[50] = (fr_mul(proof[127], proof[127]));
        // m[50] = (fr_sub(m[50], proof[127]));
        // m[50] = (fr_mul(m[50], m[19]));
        // m[51] = (fr_add(m[42], m[1]));
        // m[51] = (fr_mul(m[51], proof[127]));
        // m[48] = (fr_add(m[48], m[2]));
        // m[48] = (fr_mul(m[48], m[51]));
        update(m, proof, absorbing, uint256(48990055650782803762238340894767330787537920658767259030668742865841684439475));
        // m[48] = (fr_sub(m[46], m[48]));
        // m[48] = (fr_mul(m[16], m[48]));
        // m[51] = (fr_sub(proof[129], proof[131]));
        // m[46] = (fr_mul(m[51], m[13]));
        // m[42] = (fr_sub(proof[129], proof[130]));
        // m[51] = (fr_mul(m[42], m[51]));
        // m[51] = (fr_mul(m[16], m[51]));
        // m[42] = (fr_add(proof[134], m[1]));
        update(m, proof, absorbing, uint256(48869869583446149391576162737714362271738777895598650144948831216006653611393));
        // m[42] = (fr_mul(m[42], proof[133]));
        // m[53] = (fr_add(proof[136], m[2]));
        // m[53] = (fr_mul(m[53], m[42]));
        // m[52] = (fr_mul(proof[88], proof[67]));
        // m[52] = (fr_add(m[0], m[52]));
        // m[0] = (fr_add(m[0], proof[89]));
        // m[42] = (fr_sub(1, proof[132]));
        // m[42] = (fr_mul(m[42], m[13]));
        update(m, proof, absorbing, uint256(48198404423963036147232791092908760352163883710570489250466842261510901683597));
        // m[54] = (fr_mul(proof[132], proof[132]));
        // m[54] = (fr_sub(m[54], proof[132]));
        // m[19] = (fr_mul(m[54], m[19]));
        // m[1] = (fr_add(m[52], m[1]));
        // m[1] = (fr_mul(m[1], proof[132]));
        // m[54] = (fr_add(m[0], m[2]));
        // m[1] = (fr_mul(m[54], m[1]));
        // m[53] = (fr_sub(m[53], m[1]));
        update(m, proof, absorbing, uint256(49551284715929918367156045608035068071379549634600224398803303134162345225089));
        // m[53] = (fr_mul(m[16], m[53]));
        // m[1] = (fr_sub(proof[134], proof[136]));
        // m[13] = (fr_mul(m[1], m[13]));
        // m[54] = (fr_sub(proof[134], proof[135]));
        // m[1] = (fr_mul(m[54], m[1]));
        // m[16] = (fr_mul(m[16], m[1]));
        // m[1] = (fr_mul(m[3], 0));
        // m[1] = (fr_add(m[1], m[15]));
        update(m, proof, absorbing, uint256(49441914061213350135330212161298541850414152396358229823394490593814444966799));
        // m[1] = (fr_mul(m[3], m[1]));
        // m[54] = (fr_add(m[1], m[12]));
        // m[54] = (fr_mul(m[3], m[54]));
        // m[54] = (fr_add(m[54], m[18]));
        // m[54] = (fr_mul(m[3], m[54]));
        // m[54] = (fr_add(m[54], m[17]));
        // m[54] = (fr_mul(m[3], m[54]));
        // m[20] = (fr_add(m[54], m[20]));
        update(m, proof, absorbing, uint256(43561666183703194515232317009050698244303839766276851408930538181786111274388));
        // m[20] = (fr_mul(m[3], m[20]));
        // m[20] = (fr_add(m[20], m[14]));
        // m[20] = (fr_mul(m[3], m[20]));
        // m[20] = (fr_add(m[20], m[24]));
        // m[20] = (fr_mul(m[3], m[20]));
        // m[20] = (fr_add(m[20], m[25]));
        // m[20] = (fr_mul(m[3], m[20]));
        // m[20] = (fr_add(m[20], m[21]));
        update(m, proof, absorbing, uint256(45710152725817603132676492650801553802698447470461558927397012458216006035861));
        // m[20] = (fr_mul(m[3], m[20]));
        // m[20] = (fr_add(m[20], m[26]));
        // m[20] = (fr_mul(m[3], m[20]));
        // m[20] = (fr_add(m[20], m[27]));
        // m[20] = (fr_mul(m[3], m[20]));
        // m[20] = (fr_add(m[20], m[23]));
        // m[20] = (fr_mul(m[3], m[20]));
        // m[20] = (fr_add(m[20], m[30]));
        update(m, proof, absorbing, uint256(45710152725817603208001713475441722969748767649716371310978508125932305721758));
        // m[20] = (fr_mul(m[3], m[20]));
        // m[20] = (fr_add(m[20], m[28]));
        // m[20] = (fr_mul(m[3], m[20]));
        // m[20] = (fr_add(m[20], m[29]));
        // m[20] = (fr_mul(m[3], m[20]));
        // m[20] = (fr_add(m[20], m[33]));
        // m[20] = (fr_mul(m[3], m[20]));
        // m[20] = (fr_add(m[20], m[34]));
        update(m, proof, absorbing, uint256(45710152725817603220555916946215084498100911229973581070294435670461006686626));
        // m[20] = (fr_mul(m[3], m[20]));
        // m[20] = (fr_add(m[20], m[35]));
        // m[20] = (fr_mul(m[3], m[20]));
        // m[31] = (fr_add(m[20], m[31]));
        // m[31] = (fr_mul(m[3], m[31]));
        // m[31] = (fr_add(m[31], m[36]));
        // m[31] = (fr_mul(m[3], m[31]));
        // m[31] = (fr_add(m[31], m[32]));
        update(m, proof, absorbing, uint256(45710152725817603264495629093937549570255422862821533549633620338740960903072));
        // m[31] = (fr_mul(m[3], m[31]));
        // m[31] = (fr_add(m[31], m[37]));
        // m[31] = (fr_mul(m[3], m[31]));
        // m[37] = (fr_add(m[31], m[40]));
        // m[37] = (fr_mul(m[3], m[37]));
        // m[37] = (fr_add(m[37], m[39]));
        // m[37] = (fr_mul(m[3], m[37]));
        // m[37] = (fr_add(m[37], m[22]));
        update(m, proof, absorbing, uint256(46954013356270643338526447527659610715680373749304987286924327660753087056790));
        // m[37] = (fr_mul(m[3], m[37]));
        // m[37] = (fr_add(m[37], m[38]));
        // m[37] = (fr_mul(m[3], m[37]));
        // m[37] = (fr_add(m[37], m[44]));
        // m[37] = (fr_mul(m[3], m[37]));
        // m[37] = (fr_add(m[37], m[45]));
        // m[37] = (fr_mul(m[3], m[37]));
        // m[41] = (fr_add(m[37], m[41]));
        update(m, proof, absorbing, uint256(47632482791063210651063521061013638460076893259845760857881084614959933377449));
        // m[41] = (fr_mul(m[3], m[41]));
        // m[41] = (fr_add(m[41], m[43]));
        // m[41] = (fr_mul(m[3], m[41]));
        // m[41] = (fr_add(m[41], m[47]));
        // m[41] = (fr_mul(m[3], m[41]));
        // m[41] = (fr_add(m[41], m[49]));
        // m[41] = (fr_mul(m[3], m[41]));
        // m[41] = (fr_add(m[41], m[50]));
        update(m, proof, absorbing, uint256(48084795747591588886622344269930982590515240957583717428713505449869650121650));
        // m[41] = (fr_mul(m[3], m[41]));
        // m[41] = (fr_add(m[41], m[48]));
        // m[41] = (fr_mul(m[3], m[41]));
        // m[41] = (fr_add(m[41], m[46]));
        // m[41] = (fr_mul(m[3], m[41]));
        // m[41] = (fr_add(m[41], m[51]));
        // m[41] = (fr_mul(m[3], m[41]));
        // m[42] = (fr_add(m[41], m[42]));
        update(m, proof, absorbing, uint256(48084795747591588918007852946864386409353905706701111045798801552905477772202));
        // m[42] = (fr_mul(m[3], m[42]));
        // m[42] = (fr_add(m[42], m[19]));
        // m[42] = (fr_mul(m[3], m[42]));
        // m[42] = (fr_add(m[42], m[53]));
        // m[42] = (fr_mul(m[3], m[42]));
        // m[42] = (fr_add(m[42], m[13]));
        // m[42] = (fr_mul(m[3], m[42]));
        // m[16] = (fr_add(m[42], m[16]));
        update(m, proof, absorbing, uint256(48197873986723683287015231253646629338057627372359556497337322844169632699792));
        // m[16] = (fr_div(m[16], m[10]));
        // m[14] = (fr_mul(m[11], m[11]));
        // m[26] = (fr_mul(m[14], m[11]));
        // (m[46], m[47]) = (ecc_mul(proof[137], proof[138], m[26]));
        // (m[36], m[37]) = (ecc_mul(proof[139], proof[140], m[14]));
        // (m[46], m[47]) = (ecc_add(m[46], m[47], m[36], m[37]));
        // (m[36], m[37]) = (ecc_mul(proof[141], proof[142], m[11]));
        // (m[46], m[47]) = (ecc_add(m[46], m[47], m[36], m[37]));
        update(m, proof, absorbing, uint256(45265086441144293792706069913421516710990386420663295374910899371946923220388));
        // (m[46], m[47]) = (ecc_add(m[46], m[47], proof[143], proof[144]));
        // m[37] = (fr_mul(m[6], m[11]));
        // m[26] = (fr_mul(proof[99], m[11]));
        // m[22] = (fr_mul(proof[105], m[9]));
        // m[25] = (fr_mul(m[9], m[9]));
        // m[22] = (fr_add(m[22], proof[110]));
        // m[22] = (fr_mul(m[22], m[9]));
        // m[28] = (fr_mul(m[25], m[9]));
        update(m, proof, absorbing, uint256(106532682597839272392066689167596516127283024996859897564379237428684859061129));
        // m[22] = (fr_add(m[22], proof[115]));
        // m[22] = (fr_mul(m[22], m[9]));
        // m[2] = (fr_mul(m[28], m[9]));
        // m[22] = (fr_add(m[22], proof[120]));
        // m[22] = (fr_mul(m[22], m[9]));
        // m[35] = (fr_mul(m[2], m[9]));
        // m[22] = (fr_add(m[22], proof[125]));
        // m[22] = (fr_mul(m[22], m[9]));
        update(m, proof, absorbing, uint256(45922428848583554038320778589512028276717565443276775297808692976663126814089));
        // m[38] = (fr_mul(m[35], m[9]));
        // m[22] = (fr_add(m[22], proof[130]));
        // m[22] = (fr_mul(m[22], m[9]));
        // m[37] = (fr_mul(m[37], m[11]));
        // m[22] = (fr_add(m[26], m[22]));
        // m[22] = (fr_add(m[22], proof[135]));
        // m[22] = (fr_mul(m[22], m[11]));
        // m[26] = (fr_mul(m[7], m[11]));
        update(m, proof, absorbing, uint256(47746001959701744029117274166137813808426154984817668458694710820011542253451));
        // m[43] = (fr_mul(m[38], m[11]));
        // m[41] = (fr_mul(m[35], m[11]));
        // m[3] = (fr_mul(m[2], m[11]));
        // m[0] = (fr_mul(m[28], m[11]));
        // m[17] = (fr_mul(m[25], m[11]));
        // m[42] = (fr_mul(m[9], m[11]));
        // m[10] = (fr_mul(proof[66], m[9]));
        // m[10] = (fr_add(m[10], proof[67]));
        update(m, proof, absorbing, uint256(48311434485332368930512848600349358367371874891802999461909327089381721707587));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[10] = (fr_add(m[10], proof[68]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[10] = (fr_add(m[10], proof[69]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[10] = (fr_add(m[10], proof[70]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[10] = (fr_add(m[10], proof[71]));
        update(m, proof, absorbing, uint256(44579466931985563951542023171712474193897691572957207617562826424227776107591));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[6] = (fr_mul(m[38], m[9]));
        // m[10] = (fr_add(m[10], proof[97]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[15] = (fr_mul(m[6], m[9]));
        // m[10] = (fr_add(m[10], proof[100]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[36] = (fr_mul(m[15], m[9]));
        update(m, proof, absorbing, uint256(44579466931883634697575884220850805622926163027545967595975855256436716019593));
        // m[10] = (fr_add(m[10], proof[102]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[13] = (fr_mul(m[36], m[9]));
        // m[10] = (fr_add(m[10], proof[104]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[49] = (fr_mul(m[13], m[9]));
        // m[10] = (fr_add(m[10], proof[106]));
        // m[10] = (fr_mul(m[10], m[9]));
        update(m, proof, absorbing, uint256(44565324310126149785260292358360885535245053050888896646713951984803921204617));
        // m[39] = (fr_mul(m[49], m[9]));
        // m[10] = (fr_add(m[10], proof[107]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[21] = (fr_mul(m[39], m[9]));
        // m[10] = (fr_add(m[10], proof[109]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[50] = (fr_mul(m[21], m[9]));
        // m[10] = (fr_add(m[10], proof[111]));
        update(m, proof, absorbing, uint256(47859273420429295176031010924145021650199963544436660264402837865427345282159));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[12] = (fr_mul(m[50], m[9]));
        // m[10] = (fr_add(m[10], proof[112]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[7] = (fr_mul(m[12], m[9]));
        // m[10] = (fr_add(m[10], proof[114]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[31] = (fr_mul(m[7], m[9]));
        update(m, proof, absorbing, uint256(44579466932041641701591782238586820231502770424379388675025266895463585353609));
        // m[10] = (fr_add(m[10], proof[116]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[29] = (fr_mul(m[31], m[9]));
        // m[10] = (fr_add(m[10], proof[117]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[20] = (fr_mul(m[29], m[9]));
        // m[10] = (fr_add(m[10], proof[119]));
        // m[10] = (fr_mul(m[10], m[9]));
        update(m, proof, absorbing, uint256(44565324687565403125467325456870322077767016860083323006167428301636118713737));
        // m[40] = (fr_mul(m[20], m[9]));
        // m[10] = (fr_add(m[10], proof[121]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[54] = (fr_mul(m[40], m[9]));
        // m[10] = (fr_add(m[10], proof[122]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[24] = (fr_mul(m[54], m[9]));
        // m[10] = (fr_add(m[10], proof[124]));
        update(m, proof, absorbing, uint256(47971951331286998008304095043813186409521600815049026663659997889890122929276));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[18] = (fr_mul(m[24], m[9]));
        // m[10] = (fr_add(m[10], proof[126]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[34] = (fr_mul(m[18], m[9]));
        // m[10] = (fr_add(m[10], proof[127]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[23] = (fr_mul(m[34], m[9]));
        update(m, proof, absorbing, uint256(44579466932199526578316316571600392013641087719614451247800329590282770138505));
        // m[10] = (fr_add(m[10], proof[129]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[45] = (fr_mul(m[23], m[9]));
        // m[10] = (fr_add(m[10], proof[131]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[51] = (fr_mul(m[45], m[9]));
        // m[10] = (fr_add(m[10], proof[132]));
        // m[10] = (fr_mul(m[10], m[9]));
        update(m, proof, absorbing, uint256(44565325038044709798523716515846228593342750001706282629480308729314959889801));
        // m[19] = (fr_mul(m[51], m[9]));
        // m[10] = (fr_add(m[10], proof[134]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[30] = (fr_mul(m[19], m[9]));
        // m[10] = (fr_add(m[10], proof[136]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[44] = (fr_mul(m[30], m[9]));
        // m[10] = (fr_add(m[10], proof[73]));
        update(m, proof, absorbing, uint256(45597736784498350565901286717670757426351824758137569010971093981745417491529));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[33] = (fr_mul(m[44], m[9]));
        // m[10] = (fr_add(m[10], proof[74]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[27] = (fr_mul(m[33], m[9]));
        // m[10] = (fr_add(m[10], proof[75]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[55] = (fr_mul(m[27], m[9]));
        update(m, proof, absorbing, uint256(44579466932594511949595176305330521154729268200202461948238723411320641632137));
        // m[10] = (fr_add(m[10], proof[76]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[48] = (fr_mul(m[55], m[9]));
        // m[10] = (fr_add(m[10], proof[77]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[1] = (fr_mul(m[48], m[9]));
        // m[10] = (fr_add(m[10], proof[78]));
        // m[10] = (fr_mul(m[10], m[9]));
        update(m, proof, absorbing, uint256(44565323609167536439558221290227645658740788498701185607303589425400003892617));
        // m[53] = (fr_mul(m[1], m[9]));
        // m[10] = (fr_add(m[10], proof[79]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[52] = (fr_mul(m[53], m[9]));
        // m[10] = (fr_add(m[10], proof[80]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[32] = (fr_mul(m[52], m[9]));
        // m[10] = (fr_add(m[10], proof[81]));
        update(m, proof, absorbing, uint256(49441705822821435465455203157465083776153740803063323100512679413393262056529));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[56] = (fr_mul(m[32], m[9]));
        // m[10] = (fr_add(m[10], proof[82]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[57] = (fr_mul(m[56], m[9]));
        // m[10] = (fr_add(m[10], proof[83]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[58] = (fr_mul(m[57], m[9]));
        update(m, proof, absorbing, uint256(44579466933200019060176317924768949905477350486722355512821486178367693616009));
        // m[10] = (fr_add(m[10], proof[84]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[59] = (fr_mul(m[58], m[9]));
        // m[10] = (fr_add(m[10], proof[85]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[60] = (fr_mul(m[59], m[9]));
        // m[10] = (fr_add(m[10], proof[86]));
        // m[10] = (fr_mul(m[10], m[9]));
        update(m, proof, absorbing, uint256(44565323824847109776830771696228380407654742453224930359412036309501741045129));
        // m[61] = (fr_mul(m[60], m[9]));
        // m[10] = (fr_add(m[10], proof[87]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[62] = (fr_mul(m[61], m[9]));
        // m[10] = (fr_add(m[10], proof[88]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[63] = (fr_mul(m[62], m[9]));
        // m[10] = (fr_add(m[10], proof[89]));
        update(m, proof, absorbing, uint256(50347145926056889578945582662144926726670751682392041947294854683004567491673));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[64] = (fr_mul(m[63], m[9]));
        // m[10] = (fr_add(m[10], proof[91]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[65] = (fr_mul(m[64], m[9]));
        // m[10] = (fr_add(m[10], proof[92]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[66] = (fr_mul(m[65], m[9]));
        update(m, proof, absorbing, uint256(44579466933410743273672176368715384298475201547784789064993301204875497931657));
        // m[10] = (fr_add(m[10], proof[93]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[67] = (fr_mul(m[66], m[9]));
        // m[10] = (fr_add(m[10], proof[94]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[69] = (fr_mul(m[67], m[9]));
        // m[10] = (fr_add(m[10], proof[95]));
        // m[10] = (fr_mul(m[10], m[9]));
        update(m, proof, absorbing, uint256(44565324067486629781235575691849931144739779885410257450048570021287327372681));
        // m[68] = (fr_mul(m[69], m[9]));
        // m[10] = (fr_add(m[10], proof[96]));
        // m[10] = (fr_mul(m[10], m[9]));
        // m[71] = (fr_mul(m[8], m[8]));
        // m[70] = (fr_mul(m[71], m[8]));
        // m[73] = (fr_mul(m[68], m[9]));
        // m[16] = (fr_add(m[10], m[16]));
        // m[16] = (fr_mul(m[16], m[9]));
        update(m, proof, absorbing, uint256(51138817642511848045240989386576238077753458359301107623793934621868729246089));
        // m[10] = (fr_mul(m[70], m[9]));
        // m[71] = (fr_mul(m[71], m[9]));
        // m[70] = (fr_mul(m[8], m[9]));
        // m[8] = (fr_mul(m[37], m[11]));
        // m[14] = (fr_add(m[14], m[64]));
        // m[14] = (fr_mul(m[14], m[11]));
        // m[16] = (fr_add(m[22], m[16]));
        // m[16] = (fr_add(m[16], proof[90]));
        update(m, proof, absorbing, uint256(44580295143156680363123915882355837088234273822919217510662895935152384843866));
        // m[16] = (fr_mul(m[16], m[11]));
        // m[22] = (fr_mul(m[26], m[11]));
        // m[26] = (fr_add(m[43], m[61]));
        // m[26] = (fr_mul(m[26], m[11]));
        // m[58] = (fr_add(m[41], m[58]));
        // m[58] = (fr_mul(m[58], m[11]));
        // m[32] = (fr_add(m[3], m[32]));
        // m[32] = (fr_mul(m[32], m[11]));
        update(m, proof, absorbing, uint256(45258019080055799714016074186111374235060766700896585924430479831039600443787));
        // m[64] = (fr_add(m[0], m[1]));
        // m[64] = (fr_mul(m[64], m[11]));
        // m[61] = (fr_add(m[17], m[27]));
        // m[61] = (fr_mul(m[61], m[11]));
        // m[30] = (fr_add(m[42], m[30]));
        // m[30] = (fr_mul(m[30], m[11]));
        // m[45] = (fr_add(m[11], m[45]));
        // m[45] = (fr_mul(m[45], m[11]));
        update(m, proof, absorbing, uint256(50671417362160106520337445883689345701378191155622459636542599531005205240715));
        // m[5] = (fr_mul(m[5], m[11]));
        // m[73] = (fr_mul(m[73], m[11]));
        // m[68] = (fr_mul(m[68], m[11]));
        // m[69] = (fr_mul(m[69], m[11]));
        // m[67] = (fr_mul(m[67], m[11]));
        // m[66] = (fr_mul(m[66], m[11]));
        // m[27] = (fr_mul(m[65], m[11]));
        // m[63] = (fr_mul(m[63], m[11]));
        update(m, proof, absorbing, uint256(44014006909375070524794617789286902686853310524100053255865934625042099830667));
        // m[62] = (fr_mul(m[62], m[11]));
        // m[60] = (fr_mul(m[60], m[11]));
        // m[59] = (fr_mul(m[59], m[11]));
        // m[57] = (fr_mul(m[57], m[11]));
        // m[56] = (fr_mul(m[56], m[11]));
        // m[65] = (fr_mul(m[52], m[11]));
        // m[1] = (fr_mul(m[53], m[11]));
        // m[48] = (fr_mul(m[48], m[11]));
        update(m, proof, absorbing, uint256(50460251800427843955019116469562125449794684151483827461515388371950474584459));
        // m[55] = (fr_mul(m[55], m[11]));
        // m[33] = (fr_mul(m[33], m[11]));
        // m[44] = (fr_mul(m[44], m[11]));
        // m[19] = (fr_mul(m[19], m[11]));
        // m[51] = (fr_mul(m[51], m[11]));
        // m[23] = (fr_mul(m[23], m[11]));
        // m[34] = (fr_mul(m[34], m[11]));
        // m[18] = (fr_mul(m[18], m[11]));
        update(m, proof, absorbing, uint256(49668607690247327963963663150122630057835743556215290819765987739505079035275));
        // m[24] = (fr_mul(m[24], m[11]));
        // m[54] = (fr_mul(m[54], m[11]));
        // m[40] = (fr_mul(m[40], m[11]));
        // m[20] = (fr_mul(m[20], m[11]));
        // m[29] = (fr_mul(m[29], m[11]));
        // m[31] = (fr_mul(m[31], m[11]));
        // m[7] = (fr_mul(m[7], m[11]));
        // m[12] = (fr_mul(m[12], m[11]));
        update(m, proof, absorbing, uint256(46162755206006469461748841139733080901090167777979682103199197465327547914635));
        // m[50] = (fr_mul(m[50], m[11]));
        // m[21] = (fr_mul(m[21], m[11]));
        // m[39] = (fr_mul(m[39], m[11]));
        // m[49] = (fr_mul(m[49], m[11]));
        // m[13] = (fr_mul(m[13], m[11]));
        // m[72] = (fr_mul(m[36], m[11]));
        // m[53] = (fr_mul(m[15], m[11]));
        // m[52] = (fr_mul(m[6], m[11]));
        update(m, proof, absorbing, uint256(49103147611738801631309746174247219585602264665917299405221217789907724864907));
        // m[10] = (fr_mul(m[10], m[11]));
        // m[71] = (fr_mul(m[71], m[11]));
        // m[70] = (fr_mul(m[70], m[11]));
        // m[37] = (fr_mul(proof[72], m[9]));
        // m[37] = (fr_add(m[37], proof[98]));
        // m[37] = (fr_mul(m[37], m[9]));
        // m[37] = (fr_add(m[37], proof[101]));
        // m[37] = (fr_mul(m[37], m[9]));
        update(m, proof, absorbing, uint256(44579466987514958842324953168632063631774832878006060085640641683409880435593));
        // m[37] = (fr_add(m[37], proof[103]));
        // m[37] = (fr_mul(m[37], m[9]));
        // m[37] = (fr_add(m[37], proof[108]));
        // m[37] = (fr_mul(m[37], m[9]));
        // m[37] = (fr_add(m[37], proof[113]));
        // m[37] = (fr_mul(m[37], m[9]));
        // m[37] = (fr_add(m[37], proof[118]));
        // m[37] = (fr_mul(m[37], m[9]));
        update(m, proof, absorbing, uint256(47618808760036816007938896362766335685973580013114223110198871229380695116681));
        // m[37] = (fr_add(m[37], proof[123]));
        // m[37] = (fr_mul(m[37], m[9]));
        // m[37] = (fr_add(m[37], proof[128]));
        // m[37] = (fr_mul(m[37], m[9]));
        // (m[74], m[75]) = (ecc_mul(proof[137], proof[138], m[8]));
        // m[15] = (fr_add(m[14], m[15]));
        // (m[14], m[15]) = (ecc_mul(proof[38], proof[39], m[15]));
        // (m[14], m[15]) = (ecc_add(m[74], m[75], m[14], m[15]));
        update(m, proof, absorbing, uint256(47618809299235749350951692285336670173166718432421446608774064783306867053966));
        // m[16] = (fr_add(m[16], m[37]));
        // m[16] = (fr_add(m[16], proof[133]));
        // (m[74], m[75]) = (ecc_mul(proof[139], proof[140], m[22]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[74], m[75]));
        // (m[74], m[75]) = (ecc_mul(proof[10], proof[11], m[26]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[74], m[75]));
        // (m[74], m[75]) = (ecc_mul(proof[14], proof[15], m[58]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[74], m[75]));
        update(m, proof, absorbing, uint256(45243885004334892758750365120040234442271005599210861599890514343570103016906));
        // (m[74], m[75]) = (ecc_mul(proof[18], proof[19], m[32]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[74], m[75]));
        // (m[74], m[75]) = (ecc_mul(proof[22], proof[23], m[64]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[74], m[75]));
        // (m[74], m[75]) = (ecc_mul(proof[26], proof[27], m[61]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[74], m[75]));
        // (m[74], m[75]) = (ecc_mul(proof[30], proof[31], m[30]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[74], m[75]));
        update(m, proof, absorbing, uint256(109707327648387211650145765980617670871181096454296922606542813620591009406410));
        // (m[74], m[75]) = (ecc_mul(proof[34], proof[35], m[45]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[74], m[75]));
        // (m[74], m[75]) = (ecc_mul(proof[141], proof[142], m[5]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[74], m[75]));
        update(m, proof, absorbing, uint256(322401509803295726951146501756284247498));
        (m[74], m[75]) = (ecc_mul(instances[0], instances[1], m[73]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[74], m[75]));
        // (m[74], m[75]) = (ecc_mul(proof[0], proof[1], m[68]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[74], m[75]));
        // (m[68], m[69]) = (ecc_mul(proof[2], proof[3], m[69]));
        // (m[68], m[69]) = (ecc_add(m[14], m[15], m[68], m[69]));
        // (m[14], m[15]) = (ecc_mul(proof[4], proof[5], m[67]));
        // (m[68], m[69]) = (ecc_add(m[68], m[69], m[14], m[15]));
        // (m[14], m[15]) = (ecc_mul(proof[6], proof[7], m[66]));
        update(m, proof, absorbing, uint256(102913746604243005822143434825919705721615476585737002511014332685542266506690));
        // (m[68], m[69]) = (ecc_add(m[68], m[69], m[14], m[15]));
        // m[22] = (fr_add(m[27], m[36]));
        // (m[36], m[37]) = (ecc_mul(proof[8], proof[9], m[22]));
        // (m[36], m[37]) = (ecc_add(m[68], m[69], m[36], m[37]));
        // m[22] = (fr_add(m[63], m[6]));
        // (m[26], m[27]) = (ecc_mul(proof[40], proof[41], m[22]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[26], m[27]));
        // m[32] = (fr_add(m[62], m[38]));
        update(m, proof, absorbing, uint256(109020713816274751984993219829917243863795753715447982308451239804925844618662));
        // (m[62], m[63]) = (ecc_mul(proof[42], proof[43], m[32]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[62], m[63]));
        // (m[60], m[61]) = (ecc_mul(proof[12], proof[13], m[60]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[60], m[61]));
        // m[32] = (fr_add(m[59], m[35]));
        // (m[60], m[61]) = (ecc_mul(proof[44], proof[45], m[32]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[60], m[61]));
        // (m[60], m[61]) = (ecc_mul(proof[16], proof[17], m[57]));
        update(m, proof, absorbing, uint256(108350720387041346666127554227107526398427499751565208033354568067008263102905));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[60], m[61]));
        // m[32] = (fr_add(m[56], m[2]));
        // (m[60], m[61]) = (ecc_mul(proof[46], proof[47], m[32]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[60], m[61]));
        // (m[64], m[65]) = (ecc_mul(proof[20], proof[21], m[65]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[64], m[65]));
        // m[32] = (fr_add(m[1], m[28]));
        // (m[64], m[65]) = (ecc_mul(proof[48], proof[49], m[32]));
        update(m, proof, absorbing, uint256(105401770556263346689157310285250877596172018830419292996839253656586626556320));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[64], m[65]));
        // (m[64], m[65]) = (ecc_mul(proof[24], proof[25], m[48]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[64], m[65]));
        // m[32] = (fr_add(m[55], m[25]));
        // (m[64], m[65]) = (ecc_mul(proof[50], proof[51], m[32]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[64], m[65]));
        // (m[64], m[65]) = (ecc_mul(proof[28], proof[29], m[33]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[64], m[65]));
        update(m, proof, absorbing, uint256(105401770678427559349944539701161730700196343003574580433723163153493517617600));
        // m[32] = (fr_add(m[44], m[9]));
        // (m[8], m[9]) = (ecc_mul(proof[52], proof[53], m[32]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[8], m[9]));
        // (m[8], m[9]) = (ecc_mul(proof[32], proof[33], m[19]));
        // (m[8], m[9]) = (ecc_add(m[36], m[37], m[8], m[9]));
        // m[32] = (fr_add(1, m[51]));
        // (m[36], m[37]) = (ecc_mul(proof[54], proof[55], m[32]));
        // (m[36], m[37]) = (ecc_add(m[8], m[9], m[36], m[37]));
        update(m, proof, absorbing, uint256(47053522154856395010258183328385754698780676112067971366435505403236272509348));
        // (m[8], m[9]) = (ecc_mul(proof[36], proof[37], m[23]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[8], m[9]));
        update(m, proof, absorbing, uint256(16288474869090699656));
        (m[8], m[9]) = (ecc_mul(9116415356345615555811159776381652193168193787828239179565802674762682569973, 4428184940191662498286989946775629850985532133007156340972092328044210908854, m[34]));
        // (m[8], m[9]) = (ecc_add(m[36], m[37], m[8], m[9]));
        update(m, proof, absorbing, uint256(3792128392));
        (m[36], m[37]) = (ecc_mul(5782803705244881061263361621569960311277274931602059364909209792416853462843, 15062957458787329264595214692406450765681943945146362131527482334922095709034, m[18]));
        // (m[8], m[9]) = (ecc_add(m[8], m[9], m[36], m[37]));
        update(m, proof, absorbing, uint256(3792114084));
        (m[36], m[37]) = (ecc_mul(14644358055486067079343698621272998942731675195777908307503676891259978026953, 16295736872894509938791771324839081659430186572610185537283579311971011421292, m[24]));
        // (m[36], m[37]) = (ecc_add(m[8], m[9], m[36], m[37]));
        update(m, proof, absorbing, uint256(3909554596));
        (m[8], m[9]) = (ecc_mul(17116707133955884836357006178207620761007611328212792030784757608854661284485, 10564235754640126479094452759034342838818178798537892468702285136620994678178, m[54]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[8], m[9]));
        update(m, proof, absorbing, uint256(3909568904));
        (m[8], m[9]) = (ecc_mul(6135951017181396300356800259378210148999114301549298675044339423857898980919, 5815487117276505141264581921148900472128751426892854296990926822300013712644, m[40]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[8], m[9]));
        update(m, proof, absorbing, uint256(3909568904));
        (m[8], m[9]) = (ecc_mul(8157689213152512992213821877426256109974319146546820557446752076098013207101, 20331788656236305071458773610223833729452353814927042863466050043371792298564, m[20]));
        // (m[8], m[9]) = (ecc_add(m[36], m[37], m[8], m[9]));
        update(m, proof, absorbing, uint256(3792128392));
        (m[36], m[37]) = (ecc_mul(15608416851084762450836314372956714983290876172102962515382328946272631816537, 19602818359472118841528702513697079158282291420260785035137417435111425576917, m[29]));
        // (m[8], m[9]) = (ecc_add(m[8], m[9], m[36], m[37]));
        update(m, proof, absorbing, uint256(3792114084));
        (m[36], m[37]) = (ecc_mul(7965659214525635785209434554887419746172145594268295326365524496637495005895, 21594193019653125825171264190170924381366327572705644736196461883000697666896, m[31]));
        // (m[36], m[37]) = (ecc_add(m[8], m[9], m[36], m[37]));
        update(m, proof, absorbing, uint256(3909554596));
        (m[8], m[9]) = (ecc_mul(13914364856267104160118636963701154902761665282219140771590059906622916170099, 13262968012464745387745564604198002166707133433521463321591789339602700686829, m[7]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[8], m[9]));
        update(m, proof, absorbing, uint256(3909568904));
        (m[8], m[9]) = (ecc_mul(2918703644893990368797819857520248778893996242905236010699941158026844665879, 19496267097167811507037659097715355673325660448809069096731698348531894341840, m[12]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[8], m[9]));
        update(m, proof, absorbing, uint256(3909568904));
        (m[8], m[9]) = (ecc_mul(21537162186981550637121053147454964150809482185492418377558290311964245821909, 2173324946696678910860567153502925685634606622474439126082176533839311460335, m[50]));
        // (m[8], m[9]) = (ecc_add(m[36], m[37], m[8], m[9]));
        update(m, proof, absorbing, uint256(3792128392));
        (m[36], m[37]) = (ecc_mul(2655782365581423005140311563928797173442552504268175733975561296199753645700, 6201813071213189922368842916956898830484939074076765869016377279154166488665, m[21]));
        // (m[8], m[9]) = (ecc_add(m[8], m[9], m[36], m[37]));
        update(m, proof, absorbing, uint256(3792114084));
        (m[36], m[37]) = (ecc_mul(5422170891120229182360564594866246906567981360038071999127508208070564034524, 14722029885921976755274052080011416898514630484317773275415621146460924728182, m[39]));
        // (m[36], m[37]) = (ecc_add(m[8], m[9], m[36], m[37]));
        update(m, proof, absorbing, uint256(3909554596));
        (m[8], m[9]) = (ecc_mul(17737084440110923269096622656724713246088755105538145774000407295005556908838, 4203685513523885893207946609241749074248503765947670924993640699929083906981, m[49]));
        // (m[36], m[37]) = (ecc_add(m[36], m[37], m[8], m[9]));
        update(m, proof, absorbing, uint256(3909568904));
        (m[8], m[9]) = (ecc_mul(18451207565454686459225553564649439057698581050443267052774483067774590965003, 4419693978684087696088612463773850574955779922948673330581664932100506990694, m[13]));
        // (m[8], m[9]) = (ecc_add(m[36], m[37], m[8], m[9]));
        update(m, proof, absorbing, uint256(3792128392));
        (m[36], m[37]) = (ecc_mul(16437555853198616706213245075298393724621201055553861909595452106780033643573, 13086685446445802871119268707398694965556002011098720179711647124889361919943, m[72]));
        // (m[8], m[9]) = (ecc_add(m[8], m[9], m[36], m[37]));
        update(m, proof, absorbing, uint256(3792114084));
        (m[36], m[37]) = (ecc_mul(5422170891120229182360564594866246906567981360038071999127508208070564034524, 14722029885921976755274052080011416898514630484317773275415621146460924728182, m[53]));
        // (m[36], m[37]) = (ecc_add(m[8], m[9], m[36], m[37]));
        update(m, proof, absorbing, uint256(3909554596));
        (m[52], m[53]) = (ecc_mul(467984811404381813300121748905246620469194962855793933017395123543651662002, 9396518858838387398787470634456455001861925061455327319027891612754570465671, m[52]));
        // (m[24], m[25]) = (ecc_add(m[36], m[37], m[52], m[53]));
        update(m, proof, absorbing, uint256(3859237300));
        (m[18], m[19]) = (ecc_mul(1073209211341742528311189867664560455130715901362709093276808245867660371678, 19736041634240789293257190949105212732052786544170823808932102725097413859664, m[43]));
        // (m[24], m[25]) = (ecc_add(m[24], m[25], m[18], m[19]));
        update(m, proof, absorbing, uint256(3859231122));
        (m[18], m[19]) = (ecc_mul(11566905302404529781402371322023566311209586760145906818001162790190141985866, 13255797634361619644806915185016016139127910818219580229648105088798927340127, m[41]));
        // (m[24], m[25]) = (ecc_add(m[24], m[25], m[18], m[19]));
        update(m, proof, absorbing, uint256(3859231122));
        (m[18], m[19]) = (ecc_mul(19687193283782764679821278083169965097872078443982760551370812189881622756617, 21612445309108692993949827009335467001279824325715773969346324126663073649477, m[3]));
        // (m[24], m[25]) = (ecc_add(m[24], m[25], m[18], m[19]));
        update(m, proof, absorbing, uint256(3859231122));
        (m[18], m[19]) = (ecc_mul(8612688236720592481328836119381213598229728652791823664483828654980135610419, 13007728640223969706615008551466781366935860418326597597940783270192497225377, m[0]));
        // (m[24], m[25]) = (ecc_add(m[24], m[25], m[18], m[19]));
        update(m, proof, absorbing, uint256(3859231122));
        (m[18], m[19]) = (ecc_mul(18311107688247166194645894987623242775398986720572758069846491409878328409197, 9906741143387019721693223714748064890337165426210513616589722143371256265292, m[17]));
        // (m[24], m[25]) = (ecc_add(m[24], m[25], m[18], m[19]));
        // (m[18], m[19]) = (ecc_mul(proof[64], proof[65], m[10]));
        // (m[24], m[25]) = (ecc_add(m[24], m[25], m[18], m[19]));
        // (m[18], m[19]) = (ecc_mul(proof[62], proof[63], m[71]));
        // (m[24], m[25]) = (ecc_add(m[24], m[25], m[18], m[19]));
        // (m[18], m[19]) = (ecc_mul(proof[60], proof[61], m[70]));
        // (m[24], m[25]) = (ecc_add(m[24], m[25], m[18], m[19]));
        // (m[18], m[19]) = (ecc_mul(proof[58], proof[59], m[42]));
        update(m, proof, absorbing, uint256(104044665249396927484615936527324081987787113757838719114721946338574623077802));
        // (m[24], m[25]) = (ecc_add(m[24], m[25], m[18], m[19]));
        // (m[18], m[19]) = (ecc_mul(proof[56], proof[57], m[11]));
        // (m[24], m[25]) = (ecc_add(m[24], m[25], m[18], m[19]));
        // (m[18], m[19]) = (ecc_mul(proof[143], proof[144], m[4]));
        // (m[24], m[25]) = (ecc_add(m[24], m[25], m[18], m[19]));
        update(m, proof, absorbing, uint256(1313228300992902239240060938002073301566437667218));
        (m[18], m[19]) = (ecc_mul(1, 2, m[16]));
        // (m[24], m[25]) = (ecc_sub(m[24], m[25], m[18], m[19]));
        update(m, proof, absorbing, uint256(3859493266));
        return [ecc_from(m[46], m[47]), ecc_from(m[24], m[25])];
    }

    function verify(uint256[] memory proof, uint256[] memory instances) public view {
        // wx, wg
        G1Point[2] memory wx_wg = get_wx_wg(proof, instances);
        G1Point[] memory g1_points = new G1Point[](2);
        g1_points[0] = wx_wg[0];
        g1_points[1] = wx_wg[1];
        G2Point[] memory g2_points = new G2Point[](2);
        g2_points[0] = get_g2_s();
        g2_points[1] = get_g2_n();

        bool checked = pairing(g1_points, g2_points);
        require(checked);
    }
}
