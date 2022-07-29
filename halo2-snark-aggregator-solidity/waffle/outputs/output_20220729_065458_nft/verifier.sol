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
        // m[4] = (squeeze_challenge(absorbing, 13));
        update(m, proof, absorbing, uint256(1628707328));
        m[5] = (fr_mul(13446667982376394161563610564587413125564757801019538732601045199901075958935, m[4]));
        m[6] = (fr_mul(16569469942529664681363945218228869388192121720036659574609237682362097667612, m[4]));
        m[7] = (fr_mul(14803907026430593724305438564799066516271154714737734572920456128449769927233, m[4]));
        // m[8] = (fr_mul(m[4], m[4]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        // m[8] = (fr_mul(m[8], m[8]));
        update(m, proof, absorbing, uint256(44353227551888666404133600486901992400934088575591859585181153215213279842696));
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
        // m[10] = (squeeze_challenge(absorbing, 1));
        update(m, proof, absorbing, uint256(30301311430608612477895168));
        update_hash_point(proof[137], proof[138], absorbing, 1);
        update_hash_point(proof[139], proof[140], absorbing, 4);
        update_hash_point(proof[141], proof[142], absorbing, 7);
        update_hash_point(proof[143], proof[144], absorbing, 10);
        // m[11] = (fr_sub(m[8], 1));
        // m[12] = (fr_sub(m[4], 1));
        update(m, proof, absorbing, uint256(7118802333643507969));
        m[12] = (fr_mul(m[12], 67108864));
        // m[12] = (fr_div(m[11], m[12]));
        update(m, proof, absorbing, uint256(1662195596));
        m[13] = (fr_mul(m[11], 14803907026430593724305438564799066516271154714737734572920456128449769927233));
        m[14] = (fr_sub(m[4], 14803907026430593724305438564799066516271154714737734572920456128449769927233));
        m[14] = (fr_mul(m[14], 67108864));
        // m[14] = (fr_div(m[13], m[14]));
        update(m, proof, absorbing, uint256(1670585230));
        m[15] = (fr_mul(m[11], 11377606117859914088982205826922132024839443553408109299929510653283289974216));
        m[13] = (fr_sub(m[4], 11377606117859914088982205826922132024839443553408109299929510653283289974216));
        m[13] = (fr_mul(m[13], 67108864));
        // m[13] = (fr_div(m[15], m[13]));
        update(m, proof, absorbing, uint256(1666391949));
        m[15] = (fr_mul(m[11], 3693565015985198455139889557180396682968596245011005461846595820698933079918));
        m[17] = (fr_sub(m[4], 3693565015985198455139889557180396682968596245011005461846595820698933079918));
        m[17] = (fr_mul(m[17], 67108864));
        // m[17] = (fr_div(m[15], m[17]));
        update(m, proof, absorbing, uint256(1683169169));
        m[16] = (fr_mul(m[11], 17329448237240114492580865744088056414251735686965494637158808787419781175510));
        m[15] = (fr_sub(m[4], 17329448237240114492580865744088056414251735686965494637158808787419781175510));
        m[15] = (fr_mul(m[15], 67108864));
        // m[15] = (fr_div(m[16], m[15]));
        update(m, proof, absorbing, uint256(1674781071));
        m[16] = (fr_mul(m[11], 6047398202650739717314770882059679662647667807426525133977681644606291529311));
        m[19] = (fr_sub(m[4], 6047398202650739717314770882059679662647667807426525133977681644606291529311));
        m[19] = (fr_mul(m[19], 67108864));
        // m[19] = (fr_div(m[16], m[19]));
        update(m, proof, absorbing, uint256(1691558291));
        m[18] = (fr_mul(m[11], 16569469942529664681363945218228869388192121720036659574609237682362097667612));
        m[16] = (fr_sub(m[4], 16569469942529664681363945218228869388192121720036659574609237682362097667612));
        m[16] = (fr_mul(m[16], 67108864));
        // m[16] = (fr_div(m[18], m[16]));
        // m[14] = (fr_add(m[14], m[13]));
        // m[14] = (fr_add(m[14], m[17]));
        // m[14] = (fr_add(m[14], m[15]));
        // m[19] = (fr_add(m[14], m[19]));
        // m[14] = (fr_mul(proof[74], proof[72]));
        // m[14] = (fr_add(proof[73], m[14]));
        // m[15] = (fr_mul(proof[75], proof[67]));
        update(m, proof, absorbing, uint256(45265114209886079602858559007338219714544734625970747115376737426022312220227));
        // m[14] = (fr_add(m[14], m[15]));
        // m[15] = (fr_mul(proof[76], proof[68]));
        // m[14] = (fr_add(m[14], m[15]));
        // m[15] = (fr_mul(proof[77], proof[69]));
        // m[14] = (fr_add(m[14], m[15]));
        // m[15] = (fr_mul(proof[78], proof[70]));
        // m[14] = (fr_add(m[14], m[15]));
        // m[15] = (fr_mul(proof[79], proof[71]));
        update(m, proof, absorbing, uint256(45017700379914966953820766058402213279439558522109867169707436747659148041799));
        // m[14] = (fr_add(m[14], m[15]));
        // m[15] = (fr_mul(proof[68], proof[67]));
        // m[15] = (fr_mul(proof[80], m[15]));
        // m[14] = (fr_add(m[14], m[15]));
        // m[15] = (fr_mul(proof[70], proof[69]));
        // m[15] = (fr_mul(proof[81], m[15]));
        // m[14] = (fr_add(m[14], m[15]));
        // m[15] = (fr_sub(1, proof[97]));
        update(m, proof, absorbing, uint256(45017700379914941236541614453252887060510189533862683675878209578608496345697));
        // m[15] = (fr_mul(m[15], m[12]));
        // m[17] = (fr_mul(proof[100], proof[100]));
        // m[17] = (fr_sub(m[17], proof[100]));
        // m[17] = (fr_mul(m[17], m[16]));
        // m[13] = (fr_sub(proof[100], proof[99]));
        // m[13] = (fr_mul(m[12], m[13]));
        // m[18] = (fr_mul(m[4], m[1]));
        // m[21] = (fr_mul(proof[91], m[1]));
        update(m, proof, absorbing, uint256(45144927091244597684972852399478395749960314448978184731326878440012424984449));
        // m[21] = (fr_add(m[21], m[2]));
        // m[21] = (fr_add(proof[67], m[21]));
        // m[21] = (fr_mul(proof[98], m[21]));
        // m[20] = (fr_add(m[18], m[2]));
        // m[20] = (fr_add(proof[67], m[20]));
        // m[20] = (fr_mul(proof[97], m[20]));
        update(m, proof, absorbing, uint256(2483329521785241698034788896230326152132970468933527978900));
        m[22] = (fr_mul(m[18], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[23] = (fr_mul(proof[92], m[1]));
        // m[23] = (fr_add(m[23], m[2]));
        // m[23] = (fr_add(proof[68], m[23]));
        // m[23] = (fr_mul(m[21], m[23]));
        // m[21] = (fr_add(m[22], m[2]));
        // m[21] = (fr_add(proof[68], m[21]));
        // m[21] = (fr_mul(m[20], m[21]));
        update(m, proof, absorbing, uint256(10720760286727560125415118128202526746534165402671680780194410342805));
        m[22] = (fr_mul(m[22], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[20] = (fr_mul(proof[93], m[1]));
        // m[20] = (fr_add(m[20], m[2]));
        // m[20] = (fr_add(proof[69], m[20]));
        // m[23] = (fr_mul(m[23], m[20]));
        // m[20] = (fr_add(m[22], m[2]));
        // m[20] = (fr_add(proof[69], m[20]));
        // m[21] = (fr_mul(m[21], m[20]));
        update(m, proof, absorbing, uint256(10641779281833838562011043514922383043440871963873855483259040770964));
        m[22] = (fr_mul(m[22], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[21] = (fr_sub(m[23], m[21]));
        // m[19] = (fr_add(m[16], m[19]));
        // m[19] = (fr_sub(1, m[19]));
        // m[21] = (fr_mul(m[19], m[21]));
        update(m, proof, absorbing, uint256(134642414948103437266586280164389234581));
        m[23] = (fr_mul(11166246659983828508719468090013646171463329086121580628794302409516816350802, m[18]));
        // m[22] = (fr_mul(proof[94], m[1]));
        // m[22] = (fr_add(m[22], m[2]));
        // m[22] = (fr_add(proof[70], m[22]));
        // m[22] = (fr_mul(proof[101], m[22]));
        // m[18] = (fr_add(m[23], m[2]));
        // m[18] = (fr_add(proof[70], m[18]));
        // m[18] = (fr_mul(proof[100], m[18]));
        update(m, proof, absorbing, uint256(10694438641556467134248012020690061756165160451214116389628446296466));
        m[23] = (fr_mul(m[23], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[20] = (fr_mul(proof[95], m[1]));
        // m[20] = (fr_add(m[20], m[2]));
        // m[20] = (fr_add(proof[71], m[20]));
        // m[22] = (fr_mul(m[22], m[20]));
        // m[20] = (fr_add(m[23], m[2]));
        // m[20] = (fr_add(proof[71], m[20]));
        // m[18] = (fr_mul(m[18], m[20]));
        update(m, proof, absorbing, uint256(10641785709586015597972146031219563787568503212354594795038782203284));
        m[23] = (fr_mul(m[23], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[20] = (fr_mul(proof[96], m[1]));
        // m[20] = (fr_add(m[20], m[2]));
        // m[20] = (fr_add(proof[66], m[20]));
        // m[22] = (fr_mul(m[22], m[20]));
        // m[20] = (fr_add(m[23], m[2]));
        // m[20] = (fr_add(proof[66], m[20]));
        // m[18] = (fr_mul(m[18], m[20]));
        update(m, proof, absorbing, uint256(10641788923462104115952696244020889152291241790521587324302715200916));
        m[23] = (fr_mul(m[23], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[23] = (fr_sub(m[22], m[18]));
        // m[23] = (fr_mul(m[19], m[23]));
        // m[22] = (fr_add(proof[104], m[1]));
        // m[22] = (fr_mul(m[22], proof[103]));
        // m[18] = (fr_add(proof[106], m[2]));
        // m[22] = (fr_mul(m[18], m[22]));
        // m[18] = (fr_mul(proof[82], proof[67]));
        // m[0] = (fr_mul(m[0], 0));
        update(m, proof, absorbing, uint256(46042582186519496164255964837987036590978334433838956222417094332470105407744));
        // m[18] = (fr_add(m[0], m[18]));
        // m[20] = (fr_add(m[0], proof[83]));
        // m[24] = (fr_sub(1, proof[102]));
        // m[24] = (fr_mul(m[24], m[12]));
        // m[25] = (fr_mul(proof[102], proof[102]));
        // m[25] = (fr_sub(m[25], proof[102]));
        // m[25] = (fr_mul(m[25], m[16]));
        // m[18] = (fr_add(m[18], m[1]));
        update(m, proof, absorbing, uint256(45469820060609702531384382072267901381833759766176483973519014378249663227265));
        // m[18] = (fr_mul(m[18], proof[102]));
        // m[20] = (fr_add(m[20], m[2]));
        // m[18] = (fr_mul(m[20], m[18]));
        // m[22] = (fr_sub(m[22], m[18]));
        // m[22] = (fr_mul(m[19], m[22]));
        // m[18] = (fr_sub(proof[104], proof[106]));
        // m[26] = (fr_mul(m[18], m[12]));
        // m[27] = (fr_sub(proof[104], proof[105]));
        update(m, proof, absorbing, uint256(45484195212012480100572767552966868084902814811232585910033831069757462859881));
        // m[27] = (fr_mul(m[27], m[18]));
        // m[27] = (fr_mul(m[19], m[27]));
        // m[18] = (fr_add(proof[109], m[1]));
        // m[18] = (fr_mul(m[18], proof[108]));
        // m[28] = (fr_add(proof[111], m[2]));
        // m[28] = (fr_mul(m[28], m[18]));
        // m[29] = (fr_mul(proof[82], proof[68]));
        // m[29] = (fr_add(m[0], m[29]));
        update(m, proof, absorbing, uint256(46502031440930656312337944476768086917788193746077175070486180602955646304669));
        // m[18] = (fr_sub(1, proof[107]));
        // m[18] = (fr_mul(m[18], m[12]));
        // m[30] = (fr_mul(proof[107], proof[107]));
        // m[30] = (fr_sub(m[30], proof[107]));
        // m[30] = (fr_mul(m[30], m[16]));
        // m[31] = (fr_add(m[29], m[1]));
        // m[31] = (fr_mul(m[31], proof[107]));
        // m[31] = (fr_mul(m[20], m[31]));
        update(m, proof, absorbing, uint256(45475126452063159133881818506784987744710321083857217114882198302594329160095));
        // m[31] = (fr_sub(m[28], m[31]));
        // m[31] = (fr_mul(m[19], m[31]));
        // m[29] = (fr_sub(proof[109], proof[111]));
        // m[28] = (fr_mul(m[29], m[12]));
        // m[32] = (fr_sub(proof[109], proof[110]));
        // m[32] = (fr_mul(m[32], m[29]));
        // m[32] = (fr_mul(m[19], m[32]));
        // m[29] = (fr_add(proof[114], m[1]));
        update(m, proof, absorbing, uint256(46947291055332121734323604302629005596824630405835174531160602802901758567809));
        // m[29] = (fr_mul(m[29], proof[113]));
        // m[33] = (fr_add(proof[116], m[2]));
        // m[29] = (fr_mul(m[33], m[29]));
        // m[33] = (fr_mul(proof[82], proof[69]));
        // m[33] = (fr_add(m[0], m[33]));
        // m[34] = (fr_sub(1, proof[112]));
        // m[34] = (fr_mul(m[34], m[12]));
        // m[35] = (fr_mul(proof[112], proof[112]));
        update(m, proof, absorbing, uint256(46728207680936844751336527525470787752054378922204344064730990699703826178160));
        // m[35] = (fr_sub(m[35], proof[112]));
        // m[35] = (fr_mul(m[35], m[16]));
        // m[33] = (fr_add(m[33], m[1]));
        // m[33] = (fr_mul(m[33], proof[112]));
        // m[33] = (fr_mul(m[20], m[33]));
        // m[29] = (fr_sub(m[29], m[33]));
        // m[29] = (fr_mul(m[19], m[29]));
        // m[33] = (fr_sub(proof[114], proof[116]));
        update(m, proof, absorbing, uint256(47399692359605766663499909887071640912193613205155600881452059571598630904948));
        // m[37] = (fr_mul(m[33], m[12]));
        // m[36] = (fr_sub(proof[114], proof[115]));
        // m[36] = (fr_mul(m[36], m[33]));
        // m[36] = (fr_mul(m[19], m[36]));
        // m[33] = (fr_add(proof[119], m[1]));
        // m[33] = (fr_mul(m[33], proof[118]));
        // m[38] = (fr_add(proof[121], m[2]));
        // m[38] = (fr_mul(m[38], m[33]));
        update(m, proof, absorbing, uint256(47632896221819680250729441110838438363744471903597766664420006407729698524577));
        // m[39] = (fr_mul(proof[82], proof[70]));
        // m[39] = (fr_add(m[0], m[39]));
        // m[33] = (fr_sub(1, proof[117]));
        // m[33] = (fr_mul(m[33], m[12]));
        // m[40] = (fr_mul(proof[117], proof[117]));
        // m[40] = (fr_sub(m[40], proof[117]));
        // m[40] = (fr_mul(m[40], m[16]));
        // m[39] = (fr_add(m[39], m[1]));
        update(m, proof, absorbing, uint256(47854419687194558670136384400975616693132622212815227312735522871612726005633));
        // m[39] = (fr_mul(m[39], proof[117]));
        // m[20] = (fr_mul(m[20], m[39]));
        // m[20] = (fr_sub(m[38], m[20]));
        // m[20] = (fr_mul(m[19], m[20]));
        // m[38] = (fr_sub(proof[119], proof[121]));
        // m[39] = (fr_mul(m[38], m[12]));
        // m[41] = (fr_sub(proof[119], proof[120]));
        // m[38] = (fr_mul(m[41], m[38]));
        update(m, proof, absorbing, uint256(47859127944823685091850685507669328451350632716307744618845768634409665123238));
        // m[38] = (fr_mul(m[19], m[38]));
        // m[41] = (fr_add(proof[124], m[1]));
        // m[41] = (fr_mul(m[41], proof[123]));
        // m[42] = (fr_add(proof[126], m[2]));
        // m[42] = (fr_mul(m[42], m[41]));
        // m[43] = (fr_mul(proof[84], proof[67]));
        // m[43] = (fr_add(m[0], m[43]));
        // m[41] = (fr_add(m[0], proof[85]));
        update(m, proof, absorbing, uint256(47745781886156428751590740873192158072297046727568242028016237775367707230293));
        // m[44] = (fr_sub(1, proof[122]));
        // m[44] = (fr_mul(m[44], m[12]));
        // m[45] = (fr_mul(proof[122], proof[122]));
        // m[45] = (fr_sub(m[45], proof[122]));
        // m[45] = (fr_mul(m[45], m[16]));
        // m[43] = (fr_add(m[43], m[1]));
        // m[43] = (fr_mul(m[43], proof[122]));
        // m[41] = (fr_add(m[41], m[2]));
        update(m, proof, absorbing, uint256(48415160372938204122283906627785689748982218410622129748318135130398610903938));
        // m[43] = (fr_mul(m[41], m[43]));
        // m[42] = (fr_sub(m[42], m[43]));
        // m[42] = (fr_mul(m[19], m[42]));
        // m[43] = (fr_sub(proof[124], proof[126]));
        // m[41] = (fr_mul(m[43], m[12]));
        // m[46] = (fr_sub(proof[124], proof[125]));
        // m[46] = (fr_mul(m[46], m[43]));
        // m[46] = (fr_mul(m[19], m[46]));
        update(m, proof, absorbing, uint256(48311476758553448289314821957752094309047463231743828198710049140607003076526));
        // m[47] = (fr_add(proof[129], m[1]));
        // m[47] = (fr_mul(m[47], proof[128]));
        // m[43] = (fr_add(proof[131], m[2]));
        // m[47] = (fr_mul(m[43], m[47]));
        // m[43] = (fr_mul(proof[86], proof[67]));
        // m[43] = (fr_add(m[0], m[43]));
        // m[48] = (fr_add(m[0], proof[87]));
        // m[49] = (fr_sub(1, proof[127]));
        update(m, proof, absorbing, uint256(48745567864596727630637648526525790938075173195758590179582757485091727475327));
        // m[49] = (fr_mul(m[49], m[12]));
        // m[51] = (fr_mul(proof[127], proof[127]));
        // m[51] = (fr_sub(m[51], proof[127]));
        // m[51] = (fr_mul(m[51], m[16]));
        // m[50] = (fr_add(m[43], m[1]));
        // m[50] = (fr_mul(m[50], proof[127]));
        // m[48] = (fr_add(m[48], m[2]));
        // m[48] = (fr_mul(m[48], m[50]));
        update(m, proof, absorbing, uint256(48990055623849185168010971127228524497191033557809605755914739954907211588018));
        // m[48] = (fr_sub(m[47], m[48]));
        // m[48] = (fr_mul(m[19], m[48]));
        // m[50] = (fr_sub(proof[129], proof[131]));
        // m[43] = (fr_mul(m[50], m[12]));
        // m[47] = (fr_sub(proof[129], proof[130]));
        // m[50] = (fr_mul(m[47], m[50]));
        // m[50] = (fr_mul(m[19], m[50]));
        // m[47] = (fr_add(proof[134], m[1]));
        update(m, proof, absorbing, uint256(48869883386938852614325873178999994604487492881593655588379781682792336002433));
        // m[47] = (fr_mul(m[47], proof[133]));
        // m[53] = (fr_add(proof[136], m[2]));
        // m[53] = (fr_mul(m[53], m[47]));
        // m[52] = (fr_mul(proof[88], proof[67]));
        // m[52] = (fr_add(m[0], m[52]));
        // m[0] = (fr_add(m[0], proof[89]));
        // m[47] = (fr_sub(1, proof[132]));
        // m[47] = (fr_mul(m[47], m[12]));
        update(m, proof, absorbing, uint256(48763864502155587038337320648012625234137717659678833184512813041439009103756));
        // m[54] = (fr_mul(proof[132], proof[132]));
        // m[54] = (fr_sub(m[54], proof[132]));
        // m[54] = (fr_mul(m[54], m[16]));
        // m[55] = (fr_add(m[52], m[1]));
        // m[55] = (fr_mul(m[55], proof[132]));
        // m[2] = (fr_add(m[0], m[2]));
        // m[2] = (fr_mul(m[2], m[55]));
        // m[2] = (fr_sub(m[53], m[2]));
        update(m, proof, absorbing, uint256(49551284715929918367370594979448858974981078065806670882248297885669436124034));
        // m[2] = (fr_mul(m[19], m[2]));
        // m[55] = (fr_sub(proof[134], proof[136]));
        // m[12] = (fr_mul(m[55], m[12]));
        // m[16] = (fr_sub(proof[134], proof[135]));
        // m[16] = (fr_mul(m[16], m[55]));
        // m[19] = (fr_mul(m[19], m[16]));
        // m[16] = (fr_mul(m[3], 0));
        // m[14] = (fr_add(m[16], m[14]));
        update(m, proof, absorbing, uint256(43674965278719220339789856643731021732356048925906131283381451619124570956174));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[15]));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[17]));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[13]));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[21]));
        update(m, proof, absorbing, uint256(45031683291025035832693622588212324098794430103817442449249285500774021275029));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[23]));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[24]));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[25]));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[22]));
        update(m, proof, absorbing, uint256(45031683291025035882910436471305770211862722057925343022533112237393189477782));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[26]));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[27]));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[18]));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[30]));
        update(m, proof, absorbing, uint256(45031683291025035901741741677465812504390937428311157661101175184564630789534));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[31]));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[28]));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[32]));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[14] = (fr_add(m[14], m[34]));
        update(m, proof, absorbing, uint256(45031683291025035933127250354399216323910166911270428205334581431348505288098));
        // m[14] = (fr_mul(m[3], m[14]));
        // m[35] = (fr_add(m[14], m[35]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[29]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[37]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[36]));
        update(m, proof, absorbing, uint256(45031683291577925489624312182264253933253751913330109421954259095489725548452));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[33]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[23] = (fr_add(m[35], m[40]));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[20]));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[39]));
        update(m, proof, absorbing, uint256(47406326312799021517591355118071137512101080732143549675336520743218898743207));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[38]));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[44]));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[45]));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[42]));
        update(m, proof, absorbing, uint256(46049387443213886936456920199069847374241956076566929008382519765961953193898));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[41]));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[46]));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[49]));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[51]));
        update(m, proof, absorbing, uint256(46049387443213886955288225405229889666429889080031805183690122290512431361971));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[48]));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[43]));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[50]));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[47]));
        update(m, proof, absorbing, uint256(46049387443213886999227937552936655012259567941722654706034933323539077869487));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[54]));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[2]));
        // m[23] = (fr_mul(m[3], m[23]));
        // m[23] = (fr_add(m[23], m[12]));
        // m[3] = (fr_mul(m[3], m[23]));
        // m[3] = (fr_add(m[3], m[19]));
        update(m, proof, absorbing, uint256(46049387443213887036890547965256739581322727437210176199949370522849551779731));
        // m[11] = (fr_div(m[3], m[11]));
        // m[51] = (fr_mul(m[10], m[10]));
        // m[55] = (fr_mul(m[51], m[10]));
        // (m[0], m[1]) = (ecc_mul(proof[137], proof[138], m[55]));
        // (m[22], m[23]) = (ecc_mul(proof[139], proof[140], m[51]));
        // (m[0], m[1]) = (ecc_add(m[0], m[1], m[22], m[23]));
        // (m[22], m[23]) = (ecc_mul(proof[141], proof[142], m[10]));
        // (m[22], m[23]) = (ecc_add(m[0], m[1], m[22], m[23]));
        update(m, proof, absorbing, uint256(44699515962944276397690342095687194261460045890556265063584510487147867210134));
        // (m[22], m[23]) = (ecc_add(m[22], m[23], proof[143], proof[144]));
        // m[55] = (fr_mul(m[6], m[10]));
        // m[48] = (fr_mul(proof[99], m[10]));
        // m[24] = (fr_mul(proof[105], m[9]));
        // m[3] = (fr_mul(m[9], m[9]));
        // m[24] = (fr_add(m[24], proof[110]));
        // m[24] = (fr_mul(m[24], m[9]));
        // m[46] = (fr_mul(m[3], m[9]));
        update(m, proof, absorbing, uint256(103818474222988933421131212549065505428073752386226640850824424770262549858185));
        // m[24] = (fr_add(m[24], proof[115]));
        // m[24] = (fr_mul(m[24], m[9]));
        // m[32] = (fr_mul(m[46], m[9]));
        // m[24] = (fr_add(m[24], proof[120]));
        // m[24] = (fr_mul(m[24], m[9]));
        // m[45] = (fr_mul(m[32], m[9]));
        // m[24] = (fr_add(m[24], proof[125]));
        // m[24] = (fr_mul(m[24], m[9]));
        update(m, proof, absorbing, uint256(46148612879913236968532958972046483284975013917671464284649495718828480344457));
        // m[1] = (fr_mul(m[45], m[9]));
        // m[24] = (fr_add(m[24], proof[130]));
        // m[24] = (fr_mul(m[24], m[9]));
        // m[55] = (fr_mul(m[55], m[10]));
        // m[48] = (fr_add(m[48], m[24]));
        // m[48] = (fr_add(m[48], proof[135]));
        // m[48] = (fr_mul(m[48], m[10]));
        // m[24] = (fr_mul(m[7], m[10]));
        update(m, proof, absorbing, uint256(43562246145286128321538491469736186817036741065662057684499227067942718869386));
        // m[0] = (fr_mul(m[1], m[10]));
        // m[49] = (fr_mul(m[45], m[10]));
        // m[18] = (fr_mul(m[32], m[10]));
        // m[47] = (fr_mul(m[46], m[10]));
        // m[2] = (fr_mul(m[3], m[10]));
        // m[6] = (fr_mul(m[9], m[10]));
        // m[42] = (fr_mul(proof[66], m[9]));
        // m[42] = (fr_add(m[42], proof[67]));
        update(m, proof, absorbing, uint256(43448560607083302802541573909241374029778552721972200249923373090694108763203));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[42] = (fr_add(m[42], proof[68]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[42] = (fr_add(m[42], proof[69]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[42] = (fr_add(m[42], proof[70]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[42] = (fr_add(m[42], proof[71]));
        update(m, proof, absorbing, uint256(48198411433260490832190485721089473255731414497230575809768285756128840078407));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[34] = (fr_mul(m[1], m[9]));
        // m[42] = (fr_add(m[42], proof[97]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[13] = (fr_mul(m[34], m[9]));
        // m[42] = (fr_add(m[42], proof[100]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[33] = (fr_mul(m[13], m[9]));
        update(m, proof, absorbing, uint256(48198411433053027529105681842871861866296173838837844014634577700081657387913));
        // m[42] = (fr_add(m[42], proof[102]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[20] = (fr_mul(m[33], m[9]));
        // m[42] = (fr_add(m[42], proof[104]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[30] = (fr_mul(m[20], m[9]));
        // m[42] = (fr_add(m[42], proof[106]));
        // m[42] = (fr_mul(m[42], m[9]));
        update(m, proof, absorbing, uint256(48184268811401076665755479163541954741462647062411085474772278877066953184649));
        // m[29] = (fr_mul(m[30], m[9]));
        // m[42] = (fr_add(m[42], proof[107]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[17] = (fr_mul(m[29], m[9]));
        // m[42] = (fr_add(m[42], proof[109]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[27] = (fr_mul(m[17], m[9]));
        // m[42] = (fr_add(m[42], proof[111]));
        update(m, proof, absorbing, uint256(46728229033452552341253251446375715250523826917214386706440062242046763029615));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[14] = (fr_mul(m[27], m[9]));
        // m[42] = (fr_add(m[42], proof[112]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[40] = (fr_mul(m[14], m[9]));
        // m[42] = (fr_add(m[42], proof[114]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[44] = (fr_mul(m[40], m[9]));
        update(m, proof, absorbing, uint256(48198411432526549631541197398799124469879138668429136219265292300675347075465));
        // m[42] = (fr_add(m[42], proof[116]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[53] = (fr_mul(m[44], m[9]));
        // m[42] = (fr_add(m[42], proof[117]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[21] = (fr_mul(m[53], m[9]));
        // m[42] = (fr_add(m[42], proof[119]));
        // m[42] = (fr_mul(m[42], m[9]));
        update(m, proof, absorbing, uint256(48184269188840330006066733931451684741109684394039430056111893618518588872073));
        // m[15] = (fr_mul(m[21], m[9]));
        // m[42] = (fr_add(m[42], proof[121]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[16] = (fr_mul(m[15], m[9]));
        // m[42] = (fr_add(m[42], proof[122]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[25] = (fr_mul(m[16], m[9]));
        // m[42] = (fr_add(m[42], proof[124]));
        update(m, proof, absorbing, uint256(45145009831976877839677867355516640280748597102421664599684851174418137175164));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[31] = (fr_mul(m[25], m[9]));
        // m[42] = (fr_add(m[42], proof[126]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[28] = (fr_mul(m[31], m[9]));
        // m[42] = (fr_add(m[42], proof[127]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[38] = (fr_mul(m[28], m[9]));
        update(m, proof, absorbing, uint256(48198411432974120443380388426765196842315022501600189720711503833501784816009));
        // m[42] = (fr_add(m[42], proof[129]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[26] = (fr_mul(m[38], m[9]));
        // m[42] = (fr_add(m[42], proof[131]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[37] = (fr_mul(m[26], m[9]));
        // m[42] = (fr_add(m[42], proof[132]));
        // m[42] = (fr_mul(m[42], m[9]));
        update(m, proof, absorbing, uint256(48184269539319636678859537253976334999892370087564644226405815474059568174473));
        // m[36] = (fr_mul(m[37], m[9]));
        // m[42] = (fr_add(m[42], proof[134]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[41] = (fr_mul(m[36], m[9]));
        // m[42] = (fr_add(m[42], proof[136]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[50] = (fr_mul(m[41], m[9]));
        // m[42] = (fr_add(m[42], proof[73]));
        update(m, proof, absorbing, uint256(47519873142922123758281339668765250411734134529075279923740843513792340382793));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[54] = (fr_mul(m[50], m[9]));
        // m[42] = (fr_add(m[42], proof[74]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[39] = (fr_mul(m[54], m[9]));
        // m[42] = (fr_add(m[42], proof[75]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[19] = (fr_mul(m[39], m[9]));
        update(m, proof, absorbing, uint256(48198411433579746467376805123793917458397449108951601613835727619903699505033));
        // m[42] = (fr_add(m[42], proof[76]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[7] = (fr_mul(m[19], m[9]));
        // m[42] = (fr_add(m[42], proof[77]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[12] = (fr_mul(m[7], m[9]));
        // m[42] = (fr_add(m[42], proof[78]));
        // m[42] = (fr_mul(m[42], m[9]));
        update(m, proof, absorbing, uint256(48184268110442463319759144258030799861217873911553902182015696032097033475465));
        // m[52] = (fr_mul(m[12], m[9]));
        // m[42] = (fr_add(m[42], proof[79]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[43] = (fr_mul(m[52], m[9]));
        // m[42] = (fr_add(m[42], proof[80]));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[35] = (fr_mul(m[43], m[9]));
        // m[42] = (fr_add(m[42], proof[81]));
        update(m, proof, absorbing, uint256(49328779449937849438344669125468300392678998939258884495004670646682791662673));
        // m[42] = (fr_mul(m[42], m[9]));
        // m[57] = (fr_mul(m[35], m[9]));
        // m[56] = (fr_add(m[42], proof[82]));
        // m[56] = (fr_mul(m[56], m[9]));
        // m[42] = (fr_mul(m[57], m[9]));
        // m[56] = (fr_add(m[56], proof[83]));
        // m[56] = (fr_mul(m[56], m[9]));
        // m[58] = (fr_mul(m[42], m[9]));
        update(m, proof, absorbing, uint256(48198411433658682478072715006109576501855609047776694993073881332497632941449));
        // m[56] = (fr_add(m[56], proof[84]));
        // m[56] = (fr_mul(m[56], m[9]));
        // m[59] = (fr_mul(m[58], m[9]));
        // m[56] = (fr_add(m[56], proof[85]));
        // m[56] = (fr_mul(m[56], m[9]));
        // m[61] = (fr_mul(m[59], m[9]));
        // m[56] = (fr_add(m[56], proof[86]));
        // m[56] = (fr_mul(m[56], m[9]));
        update(m, proof, absorbing, uint256(49767556545429817167480923010151930591677253770683577971205650608073972085129));
        // m[60] = (fr_mul(m[61], m[9]));
        // m[56] = (fr_add(m[56], proof[87]));
        // m[56] = (fr_mul(m[56], m[9]));
        // m[62] = (fr_mul(m[60], m[9]));
        // m[63] = (fr_add(m[56], proof[88]));
        // m[63] = (fr_mul(m[63], m[9]));
        // m[56] = (fr_mul(m[62], m[9]));
        // m[63] = (fr_add(m[63], proof[89]));
        update(m, proof, absorbing, uint256(50234081518615005755750319566546397467739910633426950893186161289724906929753));
        // m[63] = (fr_mul(m[63], m[9]));
        // m[64] = (fr_mul(m[56], m[9]));
        // m[63] = (fr_add(m[63], proof[91]));
        // m[63] = (fr_mul(m[63], m[9]));
        // m[65] = (fr_mul(m[64], m[9]));
        // m[63] = (fr_add(m[63], proof[92]));
        // m[63] = (fr_mul(m[63], m[9]));
        // m[67] = (fr_mul(m[65], m[9]));
        update(m, proof, absorbing, uint256(50573343762251760222572498663540560092359976552495324332524023182119209501577));
        // m[63] = (fr_add(m[63], proof[93]));
        // m[63] = (fr_mul(m[63], m[9]));
        // m[66] = (fr_mul(m[67], m[9]));
        // m[63] = (fr_add(m[63], proof[94]));
        // m[63] = (fr_mul(m[63], m[9]));
        // m[69] = (fr_mul(m[66], m[9]));
        // m[63] = (fr_add(m[63], proof[95]));
        // m[63] = (fr_mul(m[63], m[9]));
        update(m, proof, absorbing, uint256(50559200897723227426978533841408961549537186265964469310012386097726495883145));
        // m[68] = (fr_mul(m[69], m[9]));
        // m[63] = (fr_add(m[63], proof[96]));
        // m[63] = (fr_mul(m[63], m[9]));
        // m[71] = (fr_mul(m[8], m[8]));
        // m[70] = (fr_mul(m[71], m[8]));
        // m[73] = (fr_mul(m[68], m[9]));
        // m[63] = (fr_add(m[63], m[11]));
        // m[63] = (fr_mul(m[63], m[9]));
        update(m, proof, absorbing, uint256(51138817643907406245606992277264858441897437695709821127352592192574202019721));
        // m[70] = (fr_mul(m[70], m[9]));
        // m[71] = (fr_mul(m[71], m[9]));
        // m[72] = (fr_mul(m[8], m[9]));
        // m[55] = (fr_mul(m[55], m[10]));
        // m[51] = (fr_add(m[51], m[64]));
        // m[51] = (fr_mul(m[51], m[10]));
        // m[48] = (fr_add(m[48], m[63]));
        // m[48] = (fr_add(m[48], proof[90]));
        update(m, proof, absorbing, uint256(51364987871905676188736038249602655077150166913858661266706015951946405863514));
        // m[48] = (fr_mul(m[48], m[10]));
        // m[63] = (fr_mul(m[24], m[10]));
        // m[24] = (fr_add(m[0], m[60]));
        // m[24] = (fr_mul(m[24], m[10]));
        // m[58] = (fr_add(m[49], m[58]));
        // m[58] = (fr_mul(m[58], m[10]));
        // m[64] = (fr_add(m[18], m[35]));
        // m[64] = (fr_mul(m[64], m[10]));
        update(m, proof, absorbing, uint256(48876963554607623305495563747435587780626988506493873904442576313808443113866));
        // m[60] = (fr_add(m[47], m[12]));
        // m[60] = (fr_mul(m[60], m[10]));
        // m[8] = (fr_add(m[2], m[39]));
        // m[8] = (fr_mul(m[8], m[10]));
        // m[41] = (fr_add(m[6], m[41]));
        // m[41] = (fr_mul(m[41], m[10]));
        // m[26] = (fr_add(m[10], m[26]));
        // m[26] = (fr_mul(m[26], m[10]));
        update(m, proof, absorbing, uint256(50219753574187526629842265076346798578430725062159835212093588522001866110346));
        // m[4] = (fr_mul(m[4], m[10]));
        // m[73] = (fr_mul(m[73], m[10]));
        // m[68] = (fr_mul(m[68], m[10]));
        // m[69] = (fr_mul(m[69], m[10]));
        // m[66] = (fr_mul(m[66], m[10]));
        // m[67] = (fr_mul(m[67], m[10]));
        // m[65] = (fr_mul(m[65], m[10]));
        // m[56] = (fr_mul(m[56], m[10]));
        update(m, proof, absorbing, uint256(43900914866776613673145970348212433859262508922869718948844050918274260496778));
        // m[62] = (fr_mul(m[62], m[10]));
        // m[61] = (fr_mul(m[61], m[10]));
        // m[59] = (fr_mul(m[59], m[10]));
        // m[42] = (fr_mul(m[42], m[10]));
        // m[57] = (fr_mul(m[57], m[10]));
        // m[39] = (fr_mul(m[43], m[10]));
        // m[52] = (fr_mul(m[52], m[10]));
        // m[7] = (fr_mul(m[7], m[10]));
        update(m, proof, absorbing, uint256(50460251773494228568384602752680547223354346056378573992863539175181259837322));
        // m[19] = (fr_mul(m[19], m[10]));
        // m[54] = (fr_mul(m[54], m[10]));
        // m[50] = (fr_mul(m[50], m[10]));
        // m[36] = (fr_mul(m[36], m[10]));
        // m[37] = (fr_mul(m[37], m[10]));
        // m[38] = (fr_mul(m[38], m[10]));
        // m[28] = (fr_mul(m[28], m[10]));
        // m[31] = (fr_mul(m[31], m[10]));
        update(m, proof, absorbing, uint256(45597295100853971897277877364967384156480622076728946332622452287704203739018));
        // m[25] = (fr_mul(m[25], m[10]));
        // m[16] = (fr_mul(m[16], m[10]));
        // m[15] = (fr_mul(m[15], m[10]));
        // m[21] = (fr_mul(m[21], m[10]));
        // m[53] = (fr_mul(m[53], m[10]));
        // m[44] = (fr_mul(m[44], m[10]));
        // m[40] = (fr_mul(m[40], m[10]));
        // m[14] = (fr_mul(m[14], m[10]));
        update(m, proof, absorbing, uint256(46275847193684444068246080299579873000045605687213746978218418561439652322698));
        // m[27] = (fr_mul(m[27], m[10]));
        // m[17] = (fr_mul(m[17], m[10]));
        // m[29] = (fr_mul(m[29], m[10]));
        // m[30] = (fr_mul(m[30], m[10]));
        // m[20] = (fr_mul(m[20], m[10]));
        // m[12] = (fr_mul(m[33], m[10]));
        // m[11] = (fr_mul(m[13], m[10]));
        // m[43] = (fr_mul(m[34], m[10]));
        update(m, proof, absorbing, uint256(46502031224987795711566950159698519230243153779395170761282040185705192179082));
        // m[70] = (fr_mul(m[70], m[10]));
        // m[71] = (fr_mul(m[71], m[10]));
        // m[72] = (fr_mul(m[72], m[10]));
        // m[35] = (fr_mul(proof[72], m[9]));
        // m[35] = (fr_add(m[35], proof[98]));
        // m[35] = (fr_mul(m[35], m[9]));
        // m[35] = (fr_add(m[35], proof[101]));
        // m[35] = (fr_mul(m[35], m[9]));
        update(m, proof, absorbing, uint256(51364987898865622862163827671574895729745720561937270628921334867909283891081));
        // m[35] = (fr_add(m[35], proof[103]));
        // m[35] = (fr_mul(m[35], m[9]));
        // m[35] = (fr_add(m[35], proof[108]));
        // m[35] = (fr_mul(m[35], m[9]));
        // m[35] = (fr_add(m[35], proof[113]));
        // m[35] = (fr_mul(m[35], m[9]));
        // m[35] = (fr_add(m[35], proof[118]));
        // m[35] = (fr_mul(m[35], m[9]));
        update(m, proof, absorbing, uint256(47392624728707133077898367453430273244608972330347137598186030021136878618505));
        // m[35] = (fr_add(m[35], proof[123]));
        // m[35] = (fr_mul(m[35], m[9]));
        // m[35] = (fr_add(m[35], proof[128]));
        // m[35] = (fr_mul(m[35], m[9]));
        // (m[74], m[75]) = (ecc_mul(proof[137], proof[138], m[55]));
        // m[51] = (fr_add(m[51], m[13]));
        // (m[76], m[77]) = (ecc_mul(proof[38], proof[39], m[51]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        update(m, proof, absorbing, uint256(47392625267906066420911163376000607731802775448508556083376928921174086751692));
        // m[51] = (fr_add(m[48], m[35]));
        // m[51] = (fr_add(m[51], proof[133]));
        // (m[76], m[77]) = (ecc_mul(proof[139], proof[140], m[63]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[10], proof[11], m[24]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[14], proof[15], m[58]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        update(m, proof, absorbing, uint256(49202064088206369956573301294005737710044630390432018034280031004295065736652));
        // (m[76], m[77]) = (ecc_mul(proof[18], proof[19], m[64]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[22], proof[23], m[60]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[26], proof[27], m[8]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[30], proof[31], m[41]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        update(m, proof, absorbing, uint256(109933484936977015413313033798699010081474066071337562791167046812327200921036));
        // (m[76], m[77]) = (ecc_mul(proof[34], proof[35], m[26]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[141], proof[142], m[4]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        update(m, proof, absorbing, uint256(323066122300495938984803628337781511628));
        (m[76], m[77]) = (ecc_mul(instances[0], instances[1], m[73]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[0], proof[1], m[68]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[2], proof[3], m[69]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[4], proof[5], m[66]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[6], proof[7], m[67]));
        update(m, proof, absorbing, uint256(109699267596526165995901191412231508640877505741941199480598176228574065593795));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // m[55] = (fr_add(m[65], m[33]));
        // (m[76], m[77]) = (ecc_mul(proof[8], proof[9], m[55]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // m[55] = (fr_add(m[56], m[34]));
        // (m[76], m[77]) = (ecc_mul(proof[40], proof[41], m[55]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[76], m[77]));
        // m[55] = (fr_add(m[62], m[1]));
        update(m, proof, absorbing, uint256(109699267582491454932629177158808862639947619443764627539035946667006134549889));
        // (m[62], m[63]) = (ecc_mul(proof[42], proof[43], m[55]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[62], m[63]));
        // (m[62], m[63]) = (ecc_mul(proof[12], proof[13], m[61]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[62], m[63]));
        // m[55] = (fr_add(m[59], m[45]));
        // (m[62], m[63]) = (ecc_mul(proof[44], proof[45], m[55]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[62], m[63]));
        // (m[62], m[63]) = (ecc_mul(proof[16], proof[17], m[42]));
        update(m, proof, absorbing, uint256(108350721008120708908747186427182706633735427059896748723229615020201116180906));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[62], m[63]));
        // m[55] = (fr_add(m[57], m[32]));
        // (m[62], m[63]) = (ecc_mul(proof[46], proof[47], m[55]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[62], m[63]));
        // (m[62], m[63]) = (ecc_mul(proof[20], proof[21], m[39]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[62], m[63]));
        // m[55] = (fr_add(m[52], m[46]));
        // (m[62], m[63]) = (ecc_mul(proof[48], proof[49], m[55]));
        update(m, proof, absorbing, uint256(109699267205052175875148618838926928115831170965513722769755148879519246213559));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[62], m[63]));
        // (m[62], m[63]) = (ecc_mul(proof[24], proof[25], m[7]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[62], m[63]));
        // m[55] = (fr_add(m[19], m[3]));
        // (m[62], m[63]) = (ecc_mul(proof[50], proof[51], m[55]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[62], m[63]));
        // (m[54], m[55]) = (ecc_mul(proof[28], proof[29], m[54]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[54], m[55]));
        update(m, proof, absorbing, uint256(109699267218718396385075202685174429238691319998814725465285064326713346332086));
        // m[55] = (fr_add(m[50], m[9]));
        // (m[54], m[55]) = (ecc_mul(proof[52], proof[53], m[55]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[54], m[55]));
        // (m[54], m[55]) = (ecc_mul(proof[32], proof[33], m[36]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[54], m[55]));
        // m[55] = (fr_add(1, m[37]));
        // (m[54], m[55]) = (ecc_mul(proof[54], proof[55], m[55]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[54], m[55]));
        update(m, proof, absorbing, uint256(49654403856377429728964961851951592698379916282633115350857771605283184285110));
        // (m[54], m[55]) = (ecc_mul(proof[36], proof[37], m[38]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[54], m[55]));
        update(m, proof, absorbing, uint256(17117137265110783414));
        (m[54], m[55]) = (ecc_mul(10434818516981658463516175232229998779718125432856881173353240215614266388342, 18359593967301049708505807915612258817076243106920407392330261372146433378809, m[28]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[54], m[55]));
        update(m, proof, absorbing, uint256(4068971958));
        (m[54], m[55]) = (ecc_mul(199053137630716607367630632976293391118255211677240179196716090787018963977, 7803397687837465809425873524186799700153583957323557798088907770515883180105, m[31]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[54], m[55]));
        update(m, proof, absorbing, uint256(4068971958));
        (m[24], m[25]) = (ecc_mul(6389597087312277583787982485343441172755547420971017034387771196649534273375, 1759553759450594995738055918677169290957672440122490234128259054785849069138, m[25]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[24], m[25]));
        update(m, proof, absorbing, uint256(4068971928));
        (m[24], m[25]) = (ecc_mul(10423120157449079831871357567749898961603234160842874814729537120495434736967, 21863588057315978019330159490528501992468046708715153486914047350133992071868, m[16]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[24], m[25]));
        update(m, proof, absorbing, uint256(4068971928));
        (m[24], m[25]) = (ecc_mul(9317137380591555288626780481563081286280477858706464549784867896583844751287, 12901511984740219941222272663040819705393006444138537998086087710247340511668, m[15]));
        // (m[24], m[25]) = (ecc_add(m[74], m[75], m[24], m[25]));
        update(m, proof, absorbing, uint256(3859256728));
        (m[74], m[75]) = (ecc_mul(18159370881964110476102102981137857025941010745304146773449817316431918457954, 13841155615121160092609095895910872378810429717988459367727895861804373226486, m[21]));
        // (m[74], m[75]) = (ecc_add(m[24], m[25], m[74], m[75]));
        update(m, proof, absorbing, uint256(4068946378));
        (m[24], m[25]) = (ecc_mul(18317646891849096138946003562486509199300956704509801904226395430695628159550, 4380883374350607989147112910639838165220295789834820985519949952285150996593, m[53]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[24], m[25]));
        update(m, proof, absorbing, uint256(4068971928));
        (m[24], m[25]) = (ecc_mul(20926247011732492175690923220946905302693580464419372749881928858015148405272, 5151750966322400917705351848956316855595322392088958979037108450854719731811, m[44]));
        // (m[24], m[25]) = (ecc_add(m[74], m[75], m[24], m[25]));
        update(m, proof, absorbing, uint256(3859256728));
        (m[74], m[75]) = (ecc_mul(13171533889038872492202681539087677402370579474235751191915382456069716831091, 21835669928248867727025379681673495609159304915225810030369292746242851950004, m[40]));
        // (m[74], m[75]) = (ecc_add(m[24], m[25], m[74], m[75]));
        update(m, proof, absorbing, uint256(4068946378));
        (m[24], m[25]) = (ecc_mul(14219186183943695445216402751002559929659494143028284143895457776060005952976, 17294082346491830933897640394945285142306797374114003807535452507312945327787, m[14]));
        // (m[24], m[25]) = (ecc_add(m[74], m[75], m[24], m[25]));
        update(m, proof, absorbing, uint256(3859256728));
        (m[74], m[75]) = (ecc_mul(21537162186981550637121053147454964150809482185492418377558290311964245821909, 2173324946696678910860567153502925685634606622474439126082176533839311460335, m[27]));
        // (m[74], m[75]) = (ecc_add(m[24], m[25], m[74], m[75]));
        update(m, proof, absorbing, uint256(4068946378));
        (m[24], m[25]) = (ecc_mul(12546721776712899138678930061654634897150120633498515322620005525312761632113, 14900787721795625196060349234819363449987798663268591278393746272279206982134, m[17]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[24], m[25]));
        update(m, proof, absorbing, uint256(4068971928));
        (m[24], m[25]) = (ecc_mul(5422170891120229182360564594866246906567981360038071999127508208070564034524, 14722029885921976755274052080011416898514630484317773275415621146460924728182, m[29]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[24], m[25]));
        update(m, proof, absorbing, uint256(4068971928));
        (m[24], m[25]) = (ecc_mul(5176318258975935420968582887032445480252338916457578635982147056728506339681, 2136919517552031013986968381893059611716028193234454444039306888735662535277, m[30]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[24], m[25]));
        update(m, proof, absorbing, uint256(4068971928));
        (m[24], m[25]) = (ecc_mul(18451207565454686459225553564649439057698581050443267052774483067774590965003, 4419693978684087696088612463773850574955779922948673330581664932100506990694, m[20]));
        // (m[74], m[75]) = (ecc_add(m[74], m[75], m[24], m[25]));
        update(m, proof, absorbing, uint256(4068971928));
        (m[24], m[25]) = (ecc_mul(19140259052066040777198243736451393002257038069718680257801780163563429401527, 1293930658737210964923894411888603545959841039309943993767131008180176469989, m[12]));
        // (m[24], m[25]) = (ecc_add(m[74], m[75], m[24], m[25]));
        update(m, proof, absorbing, uint256(3859256728));
        (m[74], m[75]) = (ecc_mul(5422170891120229182360564594866246906567981360038071999127508208070564034524, 14722029885921976755274052080011416898514630484317773275415621146460924728182, m[11]));
        // (m[74], m[75]) = (ecc_add(m[24], m[25], m[74], m[75]));
        update(m, proof, absorbing, uint256(4068946378));
        (m[24], m[25]) = (ecc_mul(3723311552449648216561251368962732449565621444087774023466151574191250356280, 14766707262380843553798766085068146132532179139139514335181445400701815089966, m[43]));
        // (m[24], m[25]) = (ecc_add(m[74], m[75], m[24], m[25]));
        update(m, proof, absorbing, uint256(3859256728));
        (m[0], m[1]) = (ecc_mul(9479183259218133439695863178148606612729292980417204472742505735953057742443, 12476139584788870902787158907646255044772737663461364566205679749515464404668, m[0]));
        // (m[0], m[1]) = (ecc_add(m[24], m[25], m[0], m[1]));
        update(m, proof, absorbing, uint256(3758567808));
        (m[48], m[49]) = (ecc_mul(20236675002937344177531217425107422787063108049967230891542363050793369433683, 14127325360736430354241725277846706813118441585921682475942820358872620780573, m[49]));
        // (m[48], m[49]) = (ecc_add(m[0], m[1], m[48], m[49]));
        update(m, proof, absorbing, uint256(3959882160));
        (m[24], m[25]) = (ecc_mul(10018737340119530286202163521837991765954940619727018476985855835543813367423, 10052809232652637783243812767959905912225047201949982169682204129241532016641, m[18]));
        // (m[48], m[49]) = (ecc_add(m[48], m[49], m[24], m[25]));
        update(m, proof, absorbing, uint256(3959906712));
        (m[24], m[25]) = (ecc_mul(17874186783772798420533068319636229665823723558202375579862837076297940854824, 11890877210737901572808330034108887853737226193934882689464776877753532824900, m[47]));
        // (m[48], m[49]) = (ecc_add(m[48], m[49], m[24], m[25]));
        update(m, proof, absorbing, uint256(3959906712));
        (m[24], m[25]) = (ecc_mul(849865825375126072677295980560188032679702207240194063449202364432043239740, 18799509977353527408390470502253772820146176482682323914019345423138707663657, m[2]));
        // (m[48], m[49]) = (ecc_add(m[48], m[49], m[24], m[25]));
        // (m[24], m[25]) = (ecc_mul(proof[64], proof[65], m[70]));
        // (m[48], m[49]) = (ecc_add(m[48], m[49], m[24], m[25]));
        // (m[24], m[25]) = (ecc_mul(proof[62], proof[63], m[71]));
        // (m[48], m[49]) = (ecc_add(m[48], m[49], m[24], m[25]));
        // (m[24], m[25]) = (ecc_mul(proof[60], proof[61], m[72]));
        // (m[48], m[49]) = (ecc_add(m[48], m[49], m[24], m[25]));
        // (m[6], m[7]) = (ecc_mul(proof[58], proof[59], m[6]));
        update(m, proof, absorbing, uint256(106758873786638820579097594567629225681797591571431844642019753184358652736902));
        // (m[48], m[49]) = (ecc_add(m[48], m[49], m[6], m[7]));
        // (m[6], m[7]) = (ecc_mul(proof[56], proof[57], m[10]));
        // (m[48], m[49]) = (ecc_add(m[48], m[49], m[6], m[7]));
        // (m[6], m[7]) = (ecc_mul(proof[143], proof[144], m[5]));
        // (m[48], m[49]) = (ecc_add(m[48], m[49], m[6], m[7]));
        update(m, proof, absorbing, uint256(1347486422920193913761311504033508404944888619398));
        (m[6], m[7]) = (ecc_mul(1, 2, m[51]));
        // (m[48], m[49]) = (ecc_sub(m[48], m[49], m[6], m[7]));
        update(m, proof, absorbing, uint256(3960168838));
        return [ecc_from(m[22], m[23]), ecc_from(m[48], m[49])];
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
