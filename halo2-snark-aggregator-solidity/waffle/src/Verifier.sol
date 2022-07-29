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
        uint256[] memory m = new uint256[](78);
        uint256[] memory absorbing = new uint256[](143);
        
        update_hash_scalar(19894504952760898935340857033351481781989043093915241645119935673803631420019, absorbing, 0);
        update_hash_point(instances[0], instances[1], absorbing, 2);
        update_hash_point(proof[0], proof[1], absorbing, 5);
        update_hash_point(proof[2], proof[3], absorbing, 8);
        update_hash_point(proof[4], proof[5], absorbing, 11);
        update_hash_point(proof[6], proof[7], absorbing, 14);
        update_hash_point(proof[8], proof[9], absorbing, 17);
        // m[1] = (squeeze_challenge(absorbing, 20));
        update(m, proof, absorbing, uint256(1616128000));
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
        // m[0] = (squeeze_challenge(absorbing, 43));
        // m[3] = (squeeze_challenge(absorbing, 1));
        update(m, proof, absorbing, uint256(6923253086799790592));
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
        // m[2] = (squeeze_challenge(absorbing, 31));
        update(m, proof, absorbing, uint256(1620327936));
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
        // m[12] = (fr_sub(m[5], 1));
        update(m, proof, absorbing, uint256(7100787935134026497));
        m[12] = (fr_mul(m[12], 67108864));
        // m[12] = (fr_div(m[10], m[12]));
        update(m, proof, absorbing, uint256(1662195084));
        m[13] = (fr_mul(m[10], 14803907026430593724305438564799066516271154714737734572920456128449769927233));
        m[14] = (fr_sub(m[5], 14803907026430593724305438564799066516271154714737734572920456128449769927233));
        m[14] = (fr_mul(m[14], 67108864));
        // m[13] = (fr_div(m[13], m[14]));
        update(m, proof, absorbing, uint256(1666390926));
        m[14] = (fr_mul(m[10], 11377606117859914088982205826922132024839443553408109299929510653283289974216));
        m[15] = (fr_sub(m[5], 11377606117859914088982205826922132024839443553408109299929510653283289974216));
        m[15] = (fr_mul(m[15], 67108864));
        // m[14] = (fr_div(m[14], m[15]));
        update(m, proof, absorbing, uint256(1670585743));
        m[15] = (fr_mul(m[10], 3693565015985198455139889557180396682968596245011005461846595820698933079918));
        m[17] = (fr_sub(m[5], 3693565015985198455139889557180396682968596245011005461846595820698933079918));
        m[17] = (fr_mul(m[17], 67108864));
        // m[15] = (fr_div(m[15], m[17]));
        update(m, proof, absorbing, uint256(1674780561));
        m[17] = (fr_mul(m[10], 17329448237240114492580865744088056414251735686965494637158808787419781175510));
        m[16] = (fr_sub(m[5], 17329448237240114492580865744088056414251735686965494637158808787419781175510));
        m[16] = (fr_mul(m[16], 67108864));
        // m[16] = (fr_div(m[17], m[16]));
        update(m, proof, absorbing, uint256(1678975888));
        m[17] = (fr_mul(m[10], 6047398202650739717314770882059679662647667807426525133977681644606291529311));
        m[18] = (fr_sub(m[5], 6047398202650739717314770882059679662647667807426525133977681644606291529311));
        m[18] = (fr_mul(m[18], 67108864));
        // m[17] = (fr_div(m[17], m[18]));
        update(m, proof, absorbing, uint256(1683170194));
        m[18] = (fr_mul(m[10], 16569469942529664681363945218228869388192121720036659574609237682362097667612));
        m[19] = (fr_sub(m[5], 16569469942529664681363945218228869388192121720036659574609237682362097667612));
        m[19] = (fr_mul(m[19], 67108864));
        // m[18] = (fr_div(m[18], m[19]));
        // m[13] = (fr_add(m[13], m[14]));
        // m[14] = (fr_add(m[13], m[15]));
        // m[14] = (fr_add(m[14], m[16]));
        // m[14] = (fr_add(m[14], m[17]));
        // m[15] = (fr_mul(proof[74], proof[72]));
        // m[15] = (fr_add(proof[73], m[15]));
        // m[13] = (fr_mul(proof[75], proof[67]));
        update(m, proof, absorbing, uint256(45491270715031221517981013640954167130874752593558821556160968485103364511299));
        // m[15] = (fr_add(m[15], m[13]));
        // m[13] = (fr_mul(proof[76], proof[68]));
        // m[15] = (fr_add(m[15], m[13]));
        // m[13] = (fr_mul(proof[77], proof[69]));
        // m[15] = (fr_add(m[15], m[13]));
        // m[13] = (fr_mul(proof[78], proof[70]));
        // m[13] = (fr_add(m[15], m[13]));
        // m[15] = (fr_mul(proof[79], proof[71]));
        update(m, proof, absorbing, uint256(45130792341580927651912244512804939529431167929925018449856935782227559358023));
        // m[15] = (fr_add(m[13], m[15]));
        // m[13] = (fr_mul(proof[68], proof[67]));
        // m[13] = (fr_mul(proof[80], m[13]));
        // m[15] = (fr_add(m[15], m[13]));
        // m[13] = (fr_mul(proof[70], proof[69]));
        // m[13] = (fr_mul(proof[81], m[13]));
        // m[15] = (fr_add(m[15], m[13]));
        // m[13] = (fr_sub(1, proof[97]));
        update(m, proof, absorbing, uint256(45130764788515408106660832063191247313337784247822386713635352780241470358113));
        // m[13] = (fr_mul(m[13], m[12]));
        // m[16] = (fr_mul(proof[100], proof[100]));
        // m[16] = (fr_sub(m[16], proof[100]));
        // m[16] = (fr_mul(m[16], m[18]));
        // m[17] = (fr_sub(proof[100], proof[99]));
        // m[17] = (fr_mul(m[12], m[17]));
        // m[19] = (fr_mul(m[5], m[0]));
        // m[20] = (fr_mul(proof[91], m[0]));
        update(m, proof, absorbing, uint256(44918743059941249255607770553231644274820557727703677210485604757689206617984));
        // m[20] = (fr_add(m[20], m[3]));
        // m[20] = (fr_add(proof[67], m[20]));
        // m[20] = (fr_mul(proof[98], m[20]));
        // m[21] = (fr_add(m[19], m[3]));
        // m[21] = (fr_add(proof[67], m[21]));
        // m[21] = (fr_mul(proof[97], m[21]));
        update(m, proof, absorbing, uint256(2477198792793014218476643672158681637178211136819488932757));
        m[23] = (fr_mul(m[19], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[22] = (fr_mul(proof[92], m[0]));
        // m[22] = (fr_add(m[22], m[3]));
        // m[22] = (fr_add(proof[68], m[22]));
        // m[20] = (fr_mul(m[20], m[22]));
        // m[22] = (fr_add(m[23], m[3]));
        // m[22] = (fr_add(proof[68], m[22]));
        // m[21] = (fr_mul(m[21], m[22]));
        update(m, proof, absorbing, uint256(10694432207527188364361730377887009836612419032524635974378112101270));
        m[23] = (fr_mul(m[23], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[22] = (fr_mul(proof[93], m[0]));
        // m[22] = (fr_add(m[22], m[3]));
        // m[22] = (fr_add(proof[69], m[22]));
        // m[20] = (fr_mul(m[20], m[22]));
        // m[22] = (fr_add(m[23], m[3]));
        // m[22] = (fr_add(proof[69], m[22]));
        // m[21] = (fr_mul(m[21], m[22]));
        update(m, proof, absorbing, uint256(10694435421403276882342281636035766382458117370178422547228130225046));
        m[23] = (fr_mul(m[23], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[23] = (fr_sub(m[20], m[21]));
        // m[14] = (fr_add(m[18], m[14]));
        // m[14] = (fr_sub(1, m[14]));
        // m[23] = (fr_mul(m[14], m[23]));
        update(m, proof, absorbing, uint256(135306907251151435827881097771134950807));
        m[19] = (fr_mul(11166246659983828508719468090013646171463329086121580628794302409516816350802, m[19]));
        // m[20] = (fr_mul(proof[94], m[0]));
        // m[20] = (fr_add(m[20], m[3]));
        // m[20] = (fr_add(proof[70], m[20]));
        // m[20] = (fr_mul(proof[101], m[20]));
        // m[21] = (fr_add(m[19], m[3]));
        // m[21] = (fr_add(proof[70], m[21]));
        // m[21] = (fr_mul(proof[100], m[21]));
        update(m, proof, absorbing, uint256(10641782489432825346066415646565243750451149939351313517813783382421));
        m[19] = (fr_mul(m[19], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[22] = (fr_mul(proof[95], m[0]));
        // m[22] = (fr_add(m[22], m[3]));
        // m[22] = (fr_add(proof[71], m[22]));
        // m[20] = (fr_mul(m[20], m[22]));
        // m[22] = (fr_add(m[19], m[3]));
        // m[22] = (fr_add(proof[71], m[22]));
        // m[21] = (fr_mul(m[21], m[22]));
        update(m, proof, absorbing, uint256(10694441849155453918303384152333279474149514007707063829971004763030));
        m[19] = (fr_mul(m[19], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[22] = (fr_mul(proof[96], m[0]));
        // m[22] = (fr_add(m[22], m[3]));
        // m[22] = (fr_add(proof[66], m[22]));
        // m[20] = (fr_mul(m[20], m[22]));
        // m[22] = (fr_add(m[19], m[3]));
        // m[22] = (fr_add(proof[66], m[22]));
        // m[21] = (fr_mul(m[21], m[22]));
        update(m, proof, absorbing, uint256(10694445063031542436283934365134604838872252585874056359234937760662));
        m[19] = (fr_mul(m[19], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[19] = (fr_sub(m[20], m[21]));
        // m[19] = (fr_mul(m[14], m[19]));
        // m[20] = (fr_add(proof[104], m[0]));
        // m[20] = (fr_mul(m[20], proof[103]));
        // m[21] = (fr_add(proof[106], m[3]));
        // m[20] = (fr_mul(m[21], m[20]));
        // m[21] = (fr_mul(proof[82], proof[67]));
        // m[1] = (fr_mul(m[1], 0));
        update(m, proof, absorbing, uint256(45590241811725354228909743638835765509204500815790678043965212260697889506048));
        // m[21] = (fr_add(m[1], m[21]));
        // m[22] = (fr_add(m[1], proof[83]));
        // m[24] = (fr_sub(1, proof[102]));
        // m[24] = (fr_mul(m[24], m[12]));
        // m[25] = (fr_mul(proof[102], proof[102]));
        // m[25] = (fr_sub(m[25], proof[102]));
        // m[25] = (fr_mul(m[25], m[18]));
        // m[21] = (fr_add(m[21], m[0]));
        update(m, proof, absorbing, uint256(45809068581472345264954236557252821649748453495990633013979452658478553181056));
        // m[21] = (fr_mul(m[21], proof[102]));
        // m[22] = (fr_add(m[22], m[3]));
        // m[21] = (fr_mul(m[22], m[21]));
        // m[20] = (fr_sub(m[20], m[21]));
        // m[20] = (fr_mul(m[14], m[20]));
        // m[21] = (fr_sub(proof[104], proof[106]));
        // m[26] = (fr_mul(m[21], m[12]));
        // m[27] = (fr_sub(proof[104], proof[105]));
        update(m, proof, absorbing, uint256(45823471258980673215117434093791141409943624226593688260984509642023207751785));
        // m[27] = (fr_mul(m[27], m[21]));
        // m[27] = (fr_mul(m[14], m[27]));
        // m[21] = (fr_add(proof[109], m[0]));
        // m[21] = (fr_mul(m[21], proof[108]));
        // m[28] = (fr_add(proof[111], m[3]));
        // m[28] = (fr_mul(m[28], m[21]));
        // m[21] = (fr_mul(proof[82], proof[68]));
        // m[21] = (fr_add(m[1], m[21]));
        update(m, proof, absorbing, uint256(46502031521810480244427811215899548053947393071768584893786308023380078953365));
        // m[29] = (fr_sub(1, proof[107]));
        // m[29] = (fr_mul(m[29], m[12]));
        // m[30] = (fr_mul(proof[107], proof[107]));
        // m[30] = (fr_sub(m[30], proof[107]));
        // m[30] = (fr_mul(m[30], m[18]));
        // m[21] = (fr_add(m[21], m[0]));
        // m[21] = (fr_mul(m[21], proof[107]));
        // m[21] = (fr_mul(m[22], m[21]));
        update(m, proof, absorbing, uint256(46718986785956785856633965908513338879148994941869552399144667022247938960789));
        // m[28] = (fr_sub(m[28], m[21]));
        // m[28] = (fr_mul(m[14], m[28]));
        // m[21] = (fr_sub(proof[109], proof[111]));
        // m[31] = (fr_mul(m[21], m[12]));
        // m[32] = (fr_sub(proof[109], proof[110]));
        // m[32] = (fr_mul(m[32], m[21]));
        // m[32] = (fr_mul(m[14], m[32]));
        // m[33] = (fr_add(proof[114], m[0]));
        update(m, proof, absorbing, uint256(46608056149216204964525007692426550045512478122385834291810696435848186226048));
        // m[33] = (fr_mul(m[33], proof[113]));
        // m[21] = (fr_add(proof[116], m[3]));
        // m[33] = (fr_mul(m[21], m[33]));
        // m[21] = (fr_mul(proof[82], proof[69]));
        // m[21] = (fr_add(m[1], m[21]));
        // m[35] = (fr_sub(1, proof[112]));
        // m[35] = (fr_mul(m[35], m[12]));
        // m[34] = (fr_mul(proof[112], proof[112]));
        update(m, proof, absorbing, uint256(47180575743174948595516092294017473826767969153790897529095967223478003490928));
        // m[34] = (fr_sub(m[34], proof[112]));
        // m[34] = (fr_mul(m[34], m[18]));
        // m[21] = (fr_add(m[21], m[0]));
        // m[21] = (fr_mul(m[21], proof[112]));
        // m[21] = (fr_mul(m[22], m[21]));
        // m[33] = (fr_sub(m[33], m[21]));
        // m[33] = (fr_mul(m[14], m[33]));
        // m[21] = (fr_sub(proof[114], proof[116]));
        update(m, proof, absorbing, uint256(47286600343940925210966410866724447383345271385974745347712177778448562447476));
        // m[36] = (fr_mul(m[21], m[12]));
        // m[37] = (fr_sub(proof[114], proof[115]));
        // m[21] = (fr_mul(m[37], m[21]));
        // m[21] = (fr_mul(m[14], m[21]));
        // m[37] = (fr_add(proof[119], m[0]));
        // m[37] = (fr_mul(m[37], proof[118]));
        // m[38] = (fr_add(proof[121], m[3]));
        // m[38] = (fr_mul(m[38], m[37]));
        update(m, proof, absorbing, uint256(47519652367787868752930401931602132179375175004159965111213458582362464931237));
        // m[39] = (fr_mul(proof[82], proof[70]));
        // m[39] = (fr_add(m[1], m[39]));
        // m[37] = (fr_sub(1, proof[117]));
        // m[37] = (fr_mul(m[37], m[12]));
        // m[40] = (fr_mul(proof[117], proof[117]));
        // m[40] = (fr_sub(m[40], proof[117]));
        // m[40] = (fr_mul(m[40], m[18]));
        // m[41] = (fr_add(m[39], m[0]));
        update(m, proof, absorbing, uint256(47854419687194561884036992847615731686459651741181043620948404263968760614784));
        // m[41] = (fr_mul(m[41], proof[117]));
        // m[41] = (fr_mul(m[22], m[41]));
        // m[41] = (fr_sub(m[38], m[41]));
        // m[41] = (fr_mul(m[14], m[41]));
        // m[38] = (fr_sub(proof[119], proof[121]));
        // m[39] = (fr_mul(m[38], m[12]));
        // m[22] = (fr_sub(proof[119], proof[120]));
        // m[38] = (fr_mul(m[22], m[38]));
        update(m, proof, absorbing, uint256(48085311976653601419987532719840644855958536418081127429217010086527433125286));
        // m[38] = (fr_mul(m[14], m[38]));
        // m[22] = (fr_add(proof[124], m[0]));
        // m[22] = (fr_mul(m[22], proof[123]));
        // m[43] = (fr_add(proof[126], m[3]));
        // m[43] = (fr_mul(m[43], m[22]));
        // m[42] = (fr_mul(proof[84], proof[67]));
        // m[42] = (fr_add(m[1], m[42]));
        // m[22] = (fr_add(m[1], proof[85]));
        update(m, proof, absorbing, uint256(47745712868192727454133634274839435646483796253106975769620378180485072224853));
        // m[44] = (fr_sub(1, proof[122]));
        // m[44] = (fr_mul(m[44], m[12]));
        // m[45] = (fr_mul(proof[122], proof[122]));
        // m[45] = (fr_sub(m[45], proof[122]));
        // m[45] = (fr_mul(m[45], m[18]));
        // m[42] = (fr_add(m[42], m[0]));
        // m[42] = (fr_mul(m[42], proof[122]));
        // m[22] = (fr_add(m[22], m[3]));
        update(m, proof, absorbing, uint256(48415160372938204122283906627785689748982218410780508692631010742907905191299));
        // m[42] = (fr_mul(m[22], m[42]));
        // m[43] = (fr_sub(m[43], m[42]));
        // m[43] = (fr_mul(m[14], m[43]));
        // m[42] = (fr_sub(proof[124], proof[126]));
        // m[22] = (fr_mul(m[42], m[12]));
        // m[47] = (fr_sub(proof[124], proof[125]));
        // m[47] = (fr_mul(m[47], m[42]));
        // m[47] = (fr_mul(m[14], m[47]));
        update(m, proof, absorbing, uint256(48198136253112838264169180923762462115010839185216299933663984668885937757615));
        // m[46] = (fr_add(proof[129], m[0]));
        // m[46] = (fr_mul(m[46], proof[128]));
        // m[42] = (fr_add(proof[131], m[3]));
        // m[46] = (fr_mul(m[42], m[46]));
        // m[42] = (fr_mul(proof[86], proof[67]));
        // m[42] = (fr_add(m[1], m[42]));
        // m[48] = (fr_add(m[1], proof[87]));
        // m[49] = (fr_sub(1, proof[127]));
        update(m, proof, absorbing, uint256(48632489625464633079594319896452809134837058295090047287973067255072216973951));
        // m[49] = (fr_mul(m[49], m[12]));
        // m[50] = (fr_mul(proof[127], proof[127]));
        // m[50] = (fr_sub(m[50], proof[127]));
        // m[50] = (fr_mul(m[50], m[18]));
        // m[42] = (fr_add(m[42], m[0]));
        // m[42] = (fr_mul(m[42], proof[127]));
        // m[48] = (fr_add(m[48], m[3]));
        // m[42] = (fr_mul(m[48], m[42]));
        update(m, proof, absorbing, uint256(48990055623822857095087701100100315700175016855138735495161803155773156450730));
        // m[46] = (fr_sub(m[46], m[42]));
        // m[46] = (fr_mul(m[14], m[46]));
        // m[42] = (fr_sub(proof[129], proof[131]));
        // m[48] = (fr_mul(m[42], m[12]));
        // m[51] = (fr_sub(proof[129], proof[130]));
        // m[42] = (fr_mul(m[51], m[42]));
        // m[42] = (fr_mul(m[14], m[42]));
        // m[51] = (fr_add(proof[134], m[0]));
        update(m, proof, absorbing, uint256(48643712997342173608289832950065436398359365538919661057262278289195419372928));
        // m[51] = (fr_mul(m[51], proof[133]));
        // m[52] = (fr_add(proof[136], m[3]));
        // m[52] = (fr_mul(m[52], m[51]));
        // m[53] = (fr_mul(proof[88], proof[67]));
        // m[53] = (fr_add(m[1], m[53]));
        // m[1] = (fr_add(m[1], proof[89]));
        // m[51] = (fr_sub(1, proof[132]));
        // m[51] = (fr_mul(m[51], m[12]));
        update(m, proof, absorbing, uint256(49216232564683299684574776000357043775468967433222344651982895746101726373772));
        // m[54] = (fr_mul(proof[132], proof[132]));
        // m[54] = (fr_sub(m[54], proof[132]));
        // m[54] = (fr_mul(m[54], m[18]));
        // m[55] = (fr_add(m[53], m[0]));
        // m[55] = (fr_mul(m[55], proof[132]));
        // m[3] = (fr_add(m[1], m[3]));
        // m[55] = (fr_mul(m[3], m[55]));
        // m[55] = (fr_sub(m[52], m[55]));
        update(m, proof, absorbing, uint256(49551284715929918367370594982371862423527173398813672758181878134015286536631));
        // m[55] = (fr_mul(m[14], m[55]));
        // m[1] = (fr_sub(proof[134], proof[136]));
        // m[12] = (fr_mul(m[1], m[12]));
        // m[3] = (fr_sub(proof[134], proof[135]));
        // m[1] = (fr_mul(m[3], m[1]));
        // m[14] = (fr_mul(m[14], m[1]));
        // m[1] = (fr_mul(m[2], 0));
        // m[1] = (fr_add(m[1], m[15]));
        update(m, proof, absorbing, uint256(49668042932439489501556874108006461661285179548944516225811538422758440895375));
        // m[1] = (fr_mul(m[2], m[1]));
        // m[3] = (fr_add(m[1], m[13]));
        // m[3] = (fr_mul(m[2], m[3]));
        // m[3] = (fr_add(m[3], m[16]));
        // m[3] = (fr_mul(m[2], m[3]));
        // m[3] = (fr_add(m[3], m[17]));
        // m[3] = (fr_mul(m[2], m[3]));
        // m[3] = (fr_add(m[3], m[23]));
        update(m, proof, absorbing, uint256(43561652378867769221295109831292337938239799104110770069702928816087169959831));
        // m[3] = (fr_mul(m[2], m[3]));
        // m[3] = (fr_add(m[3], m[19]));
        // m[3] = (fr_mul(m[2], m[3]));
        // m[24] = (fr_add(m[3], m[24]));
        // m[24] = (fr_mul(m[2], m[24]));
        // m[24] = (fr_add(m[24], m[25]));
        // m[24] = (fr_mul(m[2], m[24]));
        // m[52] = (fr_add(m[24], m[20]));
        update(m, proof, absorbing, uint256(43787808857079302215197838949032620637444146835594565655836386101049151664532));
        // m[52] = (fr_mul(m[2], m[52]));
        // m[26] = (fr_add(m[52], m[26]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[27]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[29]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[30]));
        update(m, proof, absorbing, uint256(49328642573867405364255652825690007422509531267474303148985844505266476234142));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[28]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[31]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[32]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[35]));
        update(m, proof, absorbing, uint256(46388608357117476945688313126390432096666107122151273748174480123270525302179));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[34]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[33]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[36]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[21]));
        update(m, proof, absorbing, uint256(46388608357117476983350923538710516680361408395239149171789148981213107008917));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[37]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[40]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[41]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[39]));
        update(m, proof, absorbing, uint256(46388608357117477002182228744870558974250753233308717664432071286996135785895));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[38]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[44]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[45]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[43]));
        update(m, proof, absorbing, uint256(46388608357117477008459330480257239739447672124200137934461712137482081351083));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[26] = (fr_add(m[26], m[22]));
        // m[26] = (fr_mul(m[2], m[26]));
        // m[47] = (fr_add(m[26], m[47]));
        // m[47] = (fr_mul(m[2], m[47]));
        // m[47] = (fr_add(m[47], m[49]));
        // m[47] = (fr_mul(m[2], m[47]));
        // m[47] = (fr_add(m[47], m[50]));
        update(m, proof, absorbing, uint256(46388608357117476908025702714100319720649692059785801888420003943637490032562));
        // m[47] = (fr_mul(m[2], m[47]));
        // m[47] = (fr_add(m[47], m[46]));
        // m[47] = (fr_mul(m[2], m[47]));
        // m[47] = (fr_add(m[47], m[48]));
        // m[47] = (fr_mul(m[2], m[47]));
        // m[47] = (fr_add(m[47], m[42]));
        // m[47] = (fr_mul(m[2], m[47]));
        // m[47] = (fr_add(m[47], m[51]));
        update(m, proof, absorbing, uint256(48763251378891462630586045656266372480247522752463470891326561164197246754739));
        // m[47] = (fr_mul(m[2], m[47]));
        // m[47] = (fr_add(m[47], m[54]));
        // m[47] = (fr_mul(m[2], m[47]));
        // m[47] = (fr_add(m[47], m[55]));
        // m[47] = (fr_mul(m[2], m[47]));
        // m[47] = (fr_add(m[47], m[12]));
        // m[47] = (fr_mul(m[2], m[47]));
        // m[47] = (fr_add(m[47], m[14]));
        update(m, proof, absorbing, uint256(48763251378891462680802859539359818593315814706571371463835624649720613789582));
        // m[47] = (fr_div(m[47], m[10]));
        // m[26] = (fr_mul(m[11], m[11]));
        // m[52] = (fr_mul(m[26], m[11]));
        // (m[28], m[29]) = (ecc_mul(proof[137], proof[138], m[52]));
        // (m[40], m[41]) = (ecc_mul(proof[139], proof[140], m[26]));
        // (m[28], m[29]) = (ecc_add(m[28], m[29], m[40], m[41]));
        // (m[40], m[41]) = (ecc_mul(proof[141], proof[142], m[11]));
        // (m[28], m[29]) = (ecc_add(m[28], m[29], m[40], m[41]));
        update(m, proof, absorbing, uint256(48770938926254046192719213185543104057737938763071208518097649457059131242920));
        // (m[28], m[29]) = (ecc_add(m[28], m[29], proof[143], proof[144]));
        // m[52] = (fr_mul(m[6], m[11]));
        // m[17] = (fr_mul(proof[99], m[11]));
        // m[18] = (fr_mul(proof[105], m[9]));
        // m[27] = (fr_mul(m[9], m[9]));
        // m[18] = (fr_add(m[18], proof[110]));
        // m[18] = (fr_mul(m[18], m[9]));
        // m[34] = (fr_mul(m[27], m[9]));
        update(m, proof, absorbing, uint256(104497026316741010277792302406169943638276179710427981659118774441297377703817));
        // m[18] = (fr_add(m[18], proof[115]));
        // m[18] = (fr_mul(m[18], m[9]));
        // m[41] = (fr_mul(m[34], m[9]));
        // m[18] = (fr_add(m[18], proof[120]));
        // m[18] = (fr_mul(m[18], m[9]));
        // m[22] = (fr_mul(m[41], m[9]));
        // m[18] = (fr_add(m[18], proof[125]));
        // m[18] = (fr_mul(m[18], m[9]));
        update(m, proof, absorbing, uint256(45470060785924188178503317486757219411848926969278105025585913827950551049609));
        // m[55] = (fr_mul(m[22], m[9]));
        // m[18] = (fr_add(m[18], proof[130]));
        // m[18] = (fr_mul(m[18], m[9]));
        // m[52] = (fr_mul(m[52], m[11]));
        // m[17] = (fr_add(m[17], m[18]));
        // m[17] = (fr_add(m[17], proof[135]));
        // m[17] = (fr_mul(m[17], m[11]));
        // m[18] = (fr_mul(m[7], m[11]));
        update(m, proof, absorbing, uint256(49668152120670284477847994362885771440938879991212277956315001856241815195531));
        // m[35] = (fr_mul(m[55], m[11]));
        // m[33] = (fr_mul(m[22], m[11]));
        // m[12] = (fr_mul(m[41], m[11]));
        // m[21] = (fr_mul(m[34], m[11]));
        // m[48] = (fr_mul(m[27], m[11]));
        // m[37] = (fr_mul(m[9], m[11]));
        // m[44] = (fr_mul(proof[66], m[9]));
        // m[44] = (fr_add(m[44], proof[67]));
        update(m, proof, absorbing, uint256(47407043447330960669263906977291140829026773860320199810969870200056517711939));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[44] = (fr_add(m[44], proof[68]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[44] = (fr_add(m[44], proof[69]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[44] = (fr_add(m[44], proof[70]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[44] = (fr_add(m[44], proof[71]));
        update(m, proof, absorbing, uint256(48424595464590173762231014630425535697096022179997661321781126964372656576583));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[10] = (fr_mul(m[55], m[9]));
        // m[44] = (fr_add(m[44], proof[97]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[16] = (fr_mul(m[10], m[9]));
        // m[44] = (fr_add(m[44], proof[100]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[30] = (fr_mul(m[16], m[9]));
        update(m, proof, absorbing, uint256(48424595463698347684857191973660113491774858444756420554736567002135306117513));
        // m[44] = (fr_add(m[44], proof[102]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[45] = (fr_mul(m[30], m[9]));
        // m[44] = (fr_add(m[44], proof[104]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[39] = (fr_mul(m[45], m[9]));
        // m[44] = (fr_add(m[44], proof[106]));
        // m[44] = (fr_mul(m[44], m[9]));
        update(m, proof, absorbing, uint256(48410452842730759595936993921193487390684752070243369493989559331238299261321));
        // m[49] = (fr_mul(m[39], m[9]));
        // m[44] = (fr_add(m[44], proof[107]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[42] = (fr_mul(m[49], m[9]));
        // m[44] = (fr_add(m[44], proof[109]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[14] = (fr_mul(m[42], m[9]));
        // m[44] = (fr_add(m[44], proof[111]));
        update(m, proof, absorbing, uint256(48989917507855789086866763163182521533452560985341015499378216383431343298671));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[7] = (fr_mul(m[14], m[9]));
        // m[44] = (fr_add(m[44], proof[112]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[43] = (fr_mul(m[7], m[9]));
        // m[44] = (fr_add(m[44], proof[114]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[38] = (fr_mul(m[43], m[9]));
        update(m, proof, absorbing, uint256(48424595463619231697186144868356605090093049585516205463775242845526418216841));
        // m[44] = (fr_add(m[44], proof[116]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[15] = (fr_mul(m[38], m[9]));
        // m[44] = (fr_add(m[44], proof[117]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[36] = (fr_mul(m[15], m[9]));
        // m[44] = (fr_add(m[44], proof[119]));
        // m[44] = (fr_mul(m[44], m[9]));
        update(m, proof, absorbing, uint256(48410453220170012935862057567938498457758603590170396741343088798415071435145));
        // m[0] = (fr_mul(m[36], m[9]));
        // m[44] = (fr_add(m[44], proof[121]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[19] = (fr_mul(m[0], m[9]));
        // m[44] = (fr_add(m[44], proof[122]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[54] = (fr_mul(m[19], m[9]));
        // m[44] = (fr_add(m[44], proof[124]));
        update(m, proof, absorbing, uint256(43449043702232695173790241887698250865429650314254025416069171861270051641468));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[20] = (fr_mul(m[54], m[9]));
        // m[44] = (fr_add(m[44], proof[126]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[13] = (fr_mul(m[20], m[9]));
        // m[44] = (fr_add(m[44], proof[127]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[2] = (fr_mul(m[13], m[9]));
        update(m, proof, absorbing, uint256(48424595463961625200152496464807904959655037955786666784230952498347312618377));
        // m[44] = (fr_add(m[44], proof[129]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[53] = (fr_mul(m[2], m[9]));
        // m[44] = (fr_add(m[44], proof[131]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[51] = (fr_mul(m[53], m[9]));
        // m[44] = (fr_add(m[44], proof[132]));
        // m[44] = (fr_mul(m[44], m[9]));
        update(m, proof, absorbing, uint256(48410453570649319609053287282423130417045635902155584019925888347386623777161));
        // m[24] = (fr_mul(m[51], m[9]));
        // m[44] = (fr_add(m[44], proof[134]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[3] = (fr_mul(m[24], m[9]));
        // m[44] = (fr_add(m[44], proof[136]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[1] = (fr_mul(m[3], m[9]));
        // m[44] = (fr_add(m[44], proof[73]));
        update(m, proof, absorbing, uint256(46163127846122697302546132451519260164675930982327905394305964767604577359945));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[23] = (fr_mul(m[1], m[9]));
        // m[44] = (fr_add(m[44], proof[74]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[32] = (fr_mul(m[23], m[9]));
        // m[44] = (fr_add(m[44], proof[75]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[40] = (fr_mul(m[32], m[9]));
        update(m, proof, absorbing, uint256(48424595464040439083471222825864050891235364824872795422364391269026113733001));
        // m[44] = (fr_add(m[44], proof[76]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[31] = (fr_mul(m[40], m[9]));
        // m[44] = (fr_add(m[44], proof[77]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[25] = (fr_mul(m[31], m[9]));
        // m[44] = (fr_add(m[44], proof[78]));
        // m[44] = (fr_mul(m[44], m[9]));
        update(m, proof, absorbing, uint256(48410452141772146249934546992450988477141604418157118857749335441208167586185));
        // m[50] = (fr_mul(m[25], m[9]));
        // m[44] = (fr_add(m[44], proof[79]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[6] = (fr_mul(m[50], m[9]));
        // m[44] = (fr_add(m[44], proof[80]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[46] = (fr_mul(m[6], m[9]));
        // m[44] = (fr_add(m[44], proof[81]));
        update(m, proof, absorbing, uint256(49102802471103895372415197439187482431637904779379952976443029956173075273809));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[57] = (fr_mul(m[46], m[9]));
        // m[44] = (fr_add(m[44], proof[82]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[56] = (fr_mul(m[57], m[9]));
        // m[44] = (fr_add(m[44], proof[83]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[59] = (fr_mul(m[56], m[9]));
        update(m, proof, absorbing, uint256(48424595464935738187077942233613166001790074297025671936967348946654920143241));
        // m[44] = (fr_add(m[44], proof[84]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[58] = (fr_mul(m[59], m[9]));
        // m[44] = (fr_add(m[44], proof[85]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[61] = (fr_mul(m[58], m[9]));
        // m[44] = (fr_add(m[44], proof[86]));
        // m[44] = (fr_mul(m[44], m[9]));
        update(m, proof, absorbing, uint256(48410452357451719587305189085688553127747198507002853621709133368212526684553));
        // m[60] = (fr_mul(m[61], m[9]));
        // m[44] = (fr_add(m[44], proof[87]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[62] = (fr_mul(m[60], m[9]));
        // m[44] = (fr_add(m[44], proof[88]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[63] = (fr_mul(m[62], m[9]));
        // m[44] = (fr_add(m[44], proof[89]));
        update(m, proof, absorbing, uint256(50234081518299030314158017025258407951323638728065698953173256029415733155929));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[64] = (fr_mul(m[63], m[9]));
        // m[44] = (fr_add(m[44], proof[91]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[65] = (fr_mul(m[64], m[9]));
        // m[44] = (fr_add(m[44], proof[92]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[67] = (fr_mul(m[65], m[9]));
        update(m, proof, absorbing, uint256(48424595465120089333391422129157405712928754463889638115270085881020325790601));
        // m[44] = (fr_add(m[44], proof[93]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[66] = (fr_mul(m[67], m[9]));
        // m[44] = (fr_add(m[44], proof[94]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[68] = (fr_mul(m[66], m[9]));
        // m[44] = (fr_add(m[44], proof[95]));
        // m[44] = (fr_mul(m[44], m[9]));
        update(m, proof, absorbing, uint256(48410452600091239591709993081310103864832235939188025969840756407463750621577));
        // m[69] = (fr_mul(m[68], m[9]));
        // m[44] = (fr_add(m[44], proof[96]));
        // m[44] = (fr_mul(m[44], m[9]));
        // m[70] = (fr_mul(m[8], m[8]));
        // m[71] = (fr_mul(m[70], m[8]));
        // m[73] = (fr_mul(m[69], m[9]));
        // m[47] = (fr_add(m[44], m[47]));
        // m[47] = (fr_mul(m[47], m[9]));
        update(m, proof, absorbing, uint256(51251882052060234812384936090759936690851351892241861436216533556095464988553));
        // m[44] = (fr_mul(m[71], m[9]));
        // m[70] = (fr_mul(m[70], m[9]));
        // m[71] = (fr_mul(m[8], m[9]));
        // m[52] = (fr_mul(m[52], m[11]));
        // m[26] = (fr_add(m[26], m[64]));
        // m[26] = (fr_mul(m[26], m[11]));
        // m[47] = (fr_add(m[17], m[47]));
        // m[47] = (fr_add(m[47], proof[90]));
        update(m, proof, absorbing, uint256(48424968159580806958637648281055386809165743140782258907785353984768247029338));
        // m[47] = (fr_mul(m[47], m[11]));
        // m[17] = (fr_mul(m[18], m[11]));
        // m[18] = (fr_add(m[35], m[60]));
        // m[18] = (fr_mul(m[18], m[11]));
        // m[64] = (fr_add(m[33], m[59]));
        // m[64] = (fr_mul(m[64], m[11]));
        // m[59] = (fr_add(m[12], m[46]));
        // m[59] = (fr_mul(m[59], m[11]));
        update(m, proof, absorbing, uint256(48763871564717949163220706910140643576529529167030663272666769998951601895307));
        // m[25] = (fr_add(m[21], m[25]));
        // m[25] = (fr_mul(m[25], m[11]));
        // m[32] = (fr_add(m[48], m[32]));
        // m[32] = (fr_mul(m[32], m[11]));
        // m[3] = (fr_add(m[37], m[3]));
        // m[3] = (fr_mul(m[3], m[11]));
        // m[53] = (fr_add(m[11], m[53]));
        // m[53] = (fr_mul(m[53], m[11]));
        update(m, proof, absorbing, uint256(46261657607831624263878331603523063326019975829269751590748898674623013415819));
        // m[5] = (fr_mul(m[5], m[11]));
        // m[73] = (fr_mul(m[73], m[11]));
        // m[69] = (fr_mul(m[69], m[11]));
        // m[68] = (fr_mul(m[68], m[11]));
        // m[66] = (fr_mul(m[66], m[11]));
        // m[67] = (fr_mul(m[67], m[11]));
        // m[65] = (fr_mul(m[65], m[11]));
        // m[46] = (fr_mul(m[63], m[11]));
        update(m, proof, absorbing, uint256(44014006909375070524800748519737777133791427861530049208546373194656777207691));
        // m[62] = (fr_mul(m[62], m[11]));
        // m[61] = (fr_mul(m[61], m[11]));
        // m[58] = (fr_mul(m[58], m[11]));
        // m[56] = (fr_mul(m[56], m[11]));
        // m[57] = (fr_mul(m[57], m[11]));
        // m[6] = (fr_mul(m[6], m[11]));
        // m[50] = (fr_mul(m[50], m[11]));
        // m[31] = (fr_mul(m[31], m[11]));
        update(m, proof, absorbing, uint256(50460251800454175241806213553763426749867113457651169211002751929640165523339));
        // m[40] = (fr_mul(m[40], m[11]));
        // m[23] = (fr_mul(m[23], m[11]));
        // m[1] = (fr_mul(m[1], m[11]));
        // m[24] = (fr_mul(m[24], m[11]));
        // m[51] = (fr_mul(m[51], m[11]));
        // m[2] = (fr_mul(m[2], m[11]));
        // m[13] = (fr_mul(m[13], m[11]));
        // m[20] = (fr_mul(m[20], m[11]));
        update(m, proof, absorbing, uint256(47972227455406362422454174950741410812216868833907245965986868412842972752267));
        // m[54] = (fr_mul(m[54], m[11]));
        // m[19] = (fr_mul(m[19], m[11]));
        // m[0] = (fr_mul(m[0], m[11]));
        // m[36] = (fr_mul(m[36], m[11]));
        // m[15] = (fr_mul(m[15], m[11]));
        // m[38] = (fr_mul(m[38], m[11]));
        // m[43] = (fr_mul(m[43], m[11]));
        // m[7] = (fr_mul(m[7], m[11]));
        update(m, proof, absorbing, uint256(49555515674240179770367815695515914389870195735069919412721388310791011110795));
        // m[14] = (fr_mul(m[14], m[11]));
        // m[42] = (fr_mul(m[42], m[11]));
        // m[49] = (fr_mul(m[49], m[11]));
        // m[39] = (fr_mul(m[39], m[11]));
        // m[45] = (fr_mul(m[45], m[11]));
        // m[72] = (fr_mul(m[30], m[11]));
        // m[8] = (fr_mul(m[16], m[11]));
        // m[60] = (fr_mul(m[10], m[11]));
        update(m, proof, absorbing, uint256(45031835049305392238076224842377838256445445358150716227817941461951237264779));
        // m[44] = (fr_mul(m[44], m[11]));
        // m[70] = (fr_mul(m[70], m[11]));
        // m[71] = (fr_mul(m[71], m[11]));
        // m[63] = (fr_mul(proof[72], m[9]));
        // m[63] = (fr_add(m[63], proof[98]));
        // m[63] = (fr_mul(m[63], m[9]));
        // m[63] = (fr_add(m[63], proof[101]));
        // m[63] = (fr_mul(m[63], m[9]));
        update(m, proof, absorbing, uint256(48424595519197973615048657009481668877975825724575249970408051954395850440585));
        // m[63] = (fr_add(m[63], proof[103]));
        // m[63] = (fr_mul(m[63], m[9]));
        // m[63] = (fr_add(m[63], proof[108]));
        // m[63] = (fr_mul(m[63], m[9]));
        // m[63] = (fr_add(m[63], proof[113]));
        // m[63] = (fr_mul(m[63], m[9]));
        // m[63] = (fr_add(m[63], proof[118]));
        // m[63] = (fr_mul(m[63], m[9]));
        update(m, proof, absorbing, uint256(50559201167322694098465772184135147423713479889086334766365806936550309592969));
        // m[63] = (fr_add(m[63], proof[123]));
        // m[63] = (fr_mul(m[63], m[9]));
        // m[63] = (fr_add(m[63], proof[128]));
        // m[63] = (fr_mul(m[63], m[9]));
        // (m[74], m[75]) = (ecc_mul(proof[137], proof[138], m[52]));
        // m[26] = (fr_add(m[26], m[16]));
        // (m[76], m[77]) = (ecc_mul(proof[38], proof[39], m[26]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        update(m, proof, absorbing, uint256(50559201706521627441478568106705481910897977275220535371513898194378575812044));
        // m[26] = (fr_add(m[47], m[63]));
        // m[26] = (fr_add(m[26], proof[133]));
        // (m[76], m[77]) = (ecc_mul(proof[139], proof[140], m[17]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[10], proof[11], m[18]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[14], proof[15], m[64]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        update(m, proof, absorbing, uint256(46375095735288485958499669240376925878870318617085035455210654213389913920972));
        // (m[76], m[77]) = (ecc_mul(proof[18], proof[19], m[59]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[22], proof[23], m[25]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[26], proof[27], m[32]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[30], proof[31], m[3]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        update(m, proof, absorbing, uint256(109933484802177282077559834774211377339794310567924347433736622820933356721612));
        // (m[76], m[77]) = (ecc_mul(proof[34], proof[35], m[53]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[141], proof[142], m[5]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        update(m, proof, absorbing, uint256(323066124439656326869940743367763137996));
        (m[76], m[77]) = (ecc_mul(instances[0], instances[1], m[73]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[0], proof[1], m[69]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[68], m[69]) = (ecc_mul(proof[2], proof[3], m[68]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[68], m[69]));
        // (m[68], m[69]) = (ecc_mul(proof[4], proof[5], m[66]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[68], m[69]));
        // (m[66], m[67]) = (ecc_mul(proof[6], proof[7], m[67]));
        update(m, proof, absorbing, uint256(109699267596526166002178293147606771422831365118545016875347803713595067076035));
        // (m[66], m[67]) = (ecc_add(m[74], m[75], m[66], m[67]));
        // m[47] = (fr_add(m[65], m[30]));
        // (m[74], m[75]) = (ecc_mul(proof[8], proof[9], m[47]));
        // (m[66], m[67]) = (ecc_add(m[66], m[67], m[74], m[75]));
        // m[47] = (fr_add(m[46], m[10]));
        // (m[74], m[75]) = (ecc_mul(proof[40], proof[41], m[47]));
        // (m[66], m[67]) = (ecc_add(m[66], m[67], m[74], m[75]));
        // m[47] = (fr_add(m[62], m[55]));
        update(m, proof, absorbing, uint256(108794641615514830882195451336172099557237395511489713724325654685081798147511));
        // (m[74], m[75]) = (ecc_mul(proof[42], proof[43], m[47]));
        // (m[66], m[67]) = (ecc_add(m[66], m[67], m[74], m[75]));
        // (m[74], m[75]) = (ecc_mul(proof[12], proof[13], m[61]));
        // (m[66], m[67]) = (ecc_add(m[66], m[67], m[74], m[75]));
        // m[47] = (fr_add(m[58], m[22]));
        // (m[58], m[59]) = (ecc_mul(proof[44], proof[45], m[47]));
        // (m[58], m[59]) = (ecc_add(m[66], m[67], m[58], m[59]));
        // (m[66], m[67]) = (ecc_mul(proof[16], proof[17], m[56]));
        update(m, proof, absorbing, uint256(109707659337980284517714998643767215090946252033615752656522990313461292736952));
        // (m[58], m[59]) = (ecc_add(m[58], m[59], m[66], m[67]));
        // m[47] = (fr_add(m[57], m[41]));
        // (m[66], m[67]) = (ecc_mul(proof[46], proof[47], m[47]));
        // (m[58], m[59]) = (ecc_add(m[58], m[59], m[66], m[67]));
        // (m[66], m[67]) = (ecc_mul(proof[20], proof[21], m[6]));
        // (m[58], m[59]) = (ecc_add(m[58], m[59], m[66], m[67]));
        // m[47] = (fr_add(m[50], m[34]));
        // (m[66], m[67]) = (ecc_mul(proof[48], proof[49], m[47]));
        update(m, proof, absorbing, uint256(107889795062465175165398004626669940231815159383849637081957218416936786616751));
        // (m[58], m[59]) = (ecc_add(m[58], m[59], m[66], m[67]));
        // (m[66], m[67]) = (ecc_mul(proof[24], proof[25], m[31]));
        // (m[58], m[59]) = (ecc_add(m[58], m[59], m[66], m[67]));
        // m[47] = (fr_add(m[40], m[27]));
        // (m[40], m[41]) = (ecc_mul(proof[50], proof[51], m[47]));
        // (m[40], m[41]) = (ecc_add(m[58], m[59], m[40], m[41]));
        // (m[58], m[59]) = (ecc_mul(proof[28], proof[29], m[23]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(107889795076447332644364174465470166854456436381640561785190302719014334845370));
        // m[47] = (fr_add(m[1], m[9]));
        // (m[58], m[59]) = (ecc_mul(proof[52], proof[53], m[47]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        // (m[58], m[59]) = (ecc_mul(proof[32], proof[33], m[24]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        // m[47] = (fr_add(1, m[51]));
        // (m[58], m[59]) = (ecc_mul(proof[54], proof[55], m[47]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(48749101788174223718210443399574639181684271372409059299216758883689555251642));
        // (m[58], m[59]) = (ecc_mul(proof[36], proof[37], m[2]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(17189194704387264954));
        (m[58], m[59]) = (ecc_mul(10434818516981658463516175232229998779718125432856881173353240215614266388342, 18359593967301049708505807915612258817076243106920407392330261372146433378809, m[13]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[58], m[59]) = (ecc_mul(199053137630716607367630632976293391118255211677240179196716090787018963977, 7803397687837465809425873524186799700153583957323557798088907770515883180105, m[20]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[58], m[59]) = (ecc_mul(6389597087312277583787982485343441172755547420971017034387771196649534273375, 1759553759450594995738055918677169290957672440122490234128259054785849069138, m[54]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[58], m[59]) = (ecc_mul(10423120157449079831871357567749898961603234160842874814729537120495434736967, 21863588057315978019330159490528501992468046708715153486914047350133992071868, m[19]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[58], m[59]) = (ecc_mul(9317137380591555288626780481563081286280477858706464549784867896583844751287, 12901511984740219941222272663040819705393006444138537998086087710247340511668, m[0]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[58], m[59]) = (ecc_mul(18159370881964110476102102981137857025941010745304146773449817316431918457954, 13841155615121160092609095895910872378810429717988459367727895861804373226486, m[36]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[58], m[59]) = (ecc_mul(18317646891849096138946003562486509199300956704509801904226395430695628159550, 4380883374350607989147112910639838165220295789834820985519949952285150996593, m[15]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[58], m[59]) = (ecc_mul(20926247011732492175690923220946905302693580464419372749881928858015148405272, 5151750966322400917705351848956316855595322392088958979037108450854719731811, m[38]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[58], m[59]) = (ecc_mul(13171533889038872492202681539087677402370579474235751191915382456069716831091, 21835669928248867727025379681673495609159304915225810030369292746242851950004, m[43]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[58], m[59]) = (ecc_mul(14219186183943695445216402751002559929659494143028284143895457776060005952976, 17294082346491830933897640394945285142306797374114003807535452507312945327787, m[7]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[58], m[59]) = (ecc_mul(21537162186981550637121053147454964150809482185492418377558290311964245821909, 2173324946696678910860567153502925685634606622474439126082176533839311460335, m[14]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[58], m[59]) = (ecc_mul(12546721776712899138678930061654634897150120633498515322620005525312761632113, 14900787721795625196060349234819363449987798663268591278393746272279206982134, m[42]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[58], m[59]) = (ecc_mul(5422170891120229182360564594866246906567981360038071999127508208070564034524, 14722029885921976755274052080011416898514630484317773275415621146460924728182, m[49]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[58], m[59]) = (ecc_mul(5176318258975935420968582887032445480252338916457578635982147056728506339681, 2136919517552031013986968381893059611716028193234454444039306888735662535277, m[39]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[58], m[59]) = (ecc_mul(18451207565454686459225553564649439057698581050443267052774483067774590965003, 4419693978684087696088612463773850574955779922948673330581664932100506990694, m[45]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[58], m[59]) = (ecc_mul(19140259052066040777198243736451393002257038069718680257801780163563429401527, 1293930658737210964923894411888603545959841039309943993767131008180176469989, m[72]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[58], m[59]));
        update(m, proof, absorbing, uint256(3926348218));
        (m[8], m[9]) = (ecc_mul(5422170891120229182360564594866246906567981360038071999127508208070564034524, 14722029885921976755274052080011416898514630484317773275415621146460924728182, m[8]));
        // (m[8], m[9]) = (ecc_add(m[40], m[41], m[8], m[9]));
        update(m, proof, absorbing, uint256(3792130440));
        (m[40], m[41]) = (ecc_mul(3723311552449648216561251368962732449565621444087774023466151574191250356280, 14766707262380843553798766085068146132532179139139514335181445400701815089966, m[60]));
        // (m[8], m[9]) = (ecc_add(m[8], m[9], m[40], m[41]));
        update(m, proof, absorbing, uint256(3792114088));
        (m[40], m[41]) = (ecc_mul(9479183259218133439695863178148606612729292980417204472742505735953057742443, 12476139584788870902787158907646255044772737663461364566205679749515464404668, m[35]));
        // (m[8], m[9]) = (ecc_add(m[8], m[9], m[40], m[41]));
        update(m, proof, absorbing, uint256(3792114088));
        (m[58], m[59]) = (ecc_mul(20236675002937344177531217425107422787063108049967230891542363050793369433683, 14127325360736430354241725277846706813118441585921682475942820358872620780573, m[33]));
        // (m[58], m[59]) = (ecc_add(m[8], m[9], m[58], m[59]));
        update(m, proof, absorbing, uint256(4001829306));
        (m[72], m[73]) = (ecc_mul(10018737340119530286202163521837991765954940619727018476985855835543813367423, 10052809232652637783243812767959905912225047201949982169682204129241532016641, m[12]));
        // (m[58], m[59]) = (ecc_add(m[58], m[59], m[72], m[73]));
        update(m, proof, absorbing, uint256(4001854920));
        (m[72], m[73]) = (ecc_mul(17874186783772798420533068319636229665823723558202375579862837076297940854824, 11890877210737901572808330034108887853737226193934882689464776877753532824900, m[21]));
        // (m[58], m[59]) = (ecc_add(m[58], m[59], m[72], m[73]));
        update(m, proof, absorbing, uint256(4001854920));
        (m[72], m[73]) = (ecc_mul(849865825375126072677295980560188032679702207240194063449202364432043239740, 18799509977353527408390470502253772820146176482682323914019345423138707663657, m[48]));
        // (m[58], m[59]) = (ecc_add(m[58], m[59], m[72], m[73]));
        // (m[72], m[73]) = (ecc_mul(proof[64], proof[65], m[44]));
        // (m[58], m[59]) = (ecc_add(m[58], m[59], m[72], m[73]));
        // (m[72], m[73]) = (ecc_mul(proof[62], proof[63], m[70]));
        // (m[58], m[59]) = (ecc_add(m[58], m[59], m[72], m[73]));
        // (m[72], m[73]) = (ecc_mul(proof[60], proof[61], m[71]));
        // (m[58], m[59]) = (ecc_add(m[58], m[59], m[72], m[73]));
        // (m[72], m[73]) = (ecc_mul(proof[58], proof[59], m[37]));
        update(m, proof, absorbing, uint256(107889795238365109721416712302303584891205565151165437882707053345510448199077));
        // (m[58], m[59]) = (ecc_add(m[58], m[59], m[72], m[73]));
        // (m[72], m[73]) = (ecc_mul(proof[56], proof[57], m[11]));
        // (m[58], m[59]) = (ecc_add(m[58], m[59], m[72], m[73]));
        // (m[72], m[73]) = (ecc_mul(proof[143], proof[144], m[4]));
        // (m[58], m[59]) = (ecc_add(m[58], m[59], m[72], m[73]));
        update(m, proof, absorbing, uint256(1361760664573540626569218967396451730773749757384));
        (m[72], m[73]) = (ecc_mul(1, 2, m[26]));
        // (m[58], m[59]) = (ecc_sub(m[58], m[59], m[72], m[73]));
        update(m, proof, absorbing, uint256(4002117064));
        return [ecc_from(m[28], m[29]), ecc_from(m[58], m[59])];
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
