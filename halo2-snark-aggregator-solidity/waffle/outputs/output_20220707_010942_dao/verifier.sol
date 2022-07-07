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
        m[7] = (fr_mul(16569469942529664681363945218228869388192121720036659574609237682362097667612, m[5]));
        m[6] = (fr_mul(14803907026430593724305438564799066516271154714737734572920456128449769927233, m[5]));
        // m[9] = (fr_mul(m[5], m[5]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        update(m, proof, absorbing, uint256(44466319594513454542581606473085221110142997799024064638542870453662082077577));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        update(m, proof, absorbing, uint256(44466374916324015535694465129800179674425140102444419691797601678270313468809));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        update(m, proof, absorbing, uint256(44466374916324015535694465129800179674425140102444419691797601678270313468809));
        // m[9] = (fr_mul(m[9], m[9]));
        // m[9] = (fr_mul(m[9], m[9]));
        // update_hash_scalar(proof[66], absorbing, 1);
        // update_hash_scalar(proof[67], absorbing, 3);
        // update_hash_scalar(proof[68], absorbing, 5);
        // update_hash_scalar(proof[69], absorbing, 7);
        // update_hash_scalar(proof[70], absorbing, 9);
        // update_hash_scalar(proof[71], absorbing, 11);
        update(m, proof, absorbing, uint256(44466374916324015533286286247295183818583308036474856506384770782609022684683));
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
        // m[8] = (squeeze_challenge(absorbing, 143));
        // m[10] = (squeeze_challenge(absorbing, 1));
        update(m, proof, absorbing, uint256(30301311412594213968413184));
        update_hash_point(proof[137], proof[138], absorbing, 1);
        update_hash_point(proof[139], proof[140], absorbing, 4);
        update_hash_point(proof[141], proof[142], absorbing, 7);
        update_hash_point(proof[143], proof[144], absorbing, 10);
        // m[11] = (fr_sub(m[9], 1));
        // m[12] = (fr_sub(m[5], 1));
        update(m, proof, absorbing, uint256(7118804532666764033));
        m[12] = (fr_mul(m[12], 67108864));
        // m[12] = (fr_div(m[11], m[12]));
        update(m, proof, absorbing, uint256(1662195596));
        m[13] = (fr_mul(m[11], 14803907026430593724305438564799066516271154714737734572920456128449769927233));
        m[14] = (fr_sub(m[5], 14803907026430593724305438564799066516271154714737734572920456128449769927233));
        m[14] = (fr_mul(m[14], 67108864));
        // m[14] = (fr_div(m[13], m[14]));
        update(m, proof, absorbing, uint256(1670585230));
        m[15] = (fr_mul(m[11], 11377606117859914088982205826922132024839443553408109299929510653283289974216));
        m[13] = (fr_sub(m[5], 11377606117859914088982205826922132024839443553408109299929510653283289974216));
        m[13] = (fr_mul(m[13], 67108864));
        // m[15] = (fr_div(m[15], m[13]));
        update(m, proof, absorbing, uint256(1674780557));
        m[13] = (fr_mul(m[11], 3693565015985198455139889557180396682968596245011005461846595820698933079918));
        m[17] = (fr_sub(m[5], 3693565015985198455139889557180396682968596245011005461846595820698933079918));
        m[17] = (fr_mul(m[17], 67108864));
        // m[17] = (fr_div(m[13], m[17]));
        update(m, proof, absorbing, uint256(1683168145));
        m[13] = (fr_mul(m[11], 17329448237240114492580865744088056414251735686965494637158808787419781175510));
        m[16] = (fr_sub(m[5], 17329448237240114492580865744088056414251735686965494637158808787419781175510));
        m[16] = (fr_mul(m[16], 67108864));
        // m[13] = (fr_div(m[13], m[16]));
        update(m, proof, absorbing, uint256(1666390928));
        m[16] = (fr_mul(m[11], 6047398202650739717314770882059679662647667807426525133977681644606291529311));
        m[18] = (fr_sub(m[5], 6047398202650739717314770882059679662647667807426525133977681644606291529311));
        m[18] = (fr_mul(m[18], 67108864));
        // m[18] = (fr_div(m[16], m[18]));
        update(m, proof, absorbing, uint256(1687363986));
        m[19] = (fr_mul(m[11], 16569469942529664681363945218228869388192121720036659574609237682362097667612));
        m[16] = (fr_sub(m[5], 16569469942529664681363945218228869388192121720036659574609237682362097667612));
        m[16] = (fr_mul(m[16], 67108864));
        // m[19] = (fr_div(m[19], m[16]));
        // m[14] = (fr_add(m[14], m[15]));
        // m[17] = (fr_add(m[14], m[17]));
        // m[13] = (fr_add(m[17], m[13]));
        // m[18] = (fr_add(m[13], m[18]));
        // m[13] = (fr_mul(proof[74], proof[72]));
        // m[13] = (fr_add(proof[73], m[13]));
        // m[17] = (fr_mul(proof[75], proof[67]));
        update(m, proof, absorbing, uint256(45604362649816222987838720414254910091906507996325420535326225717386174830147));
        // m[13] = (fr_add(m[13], m[17]));
        // m[17] = (fr_mul(proof[76], proof[68]));
        // m[13] = (fr_add(m[13], m[17]));
        // m[17] = (fr_mul(proof[77], proof[69]));
        // m[13] = (fr_add(m[13], m[17]));
        // m[17] = (fr_mul(proof[78], proof[70]));
        // m[13] = (fr_add(m[13], m[17]));
        // m[17] = (fr_mul(proof[79], proof[71]));
        update(m, proof, absorbing, uint256(44904608418249006255729287603999487029447949114294715889557901684293726150215));
        // m[13] = (fr_add(m[13], m[17]));
        // m[17] = (fr_mul(proof[68], proof[67]));
        // m[17] = (fr_mul(proof[80], m[17]));
        // m[13] = (fr_add(m[13], m[17]));
        // m[17] = (fr_mul(proof[70], proof[69]));
        // m[17] = (fr_mul(proof[81], m[17]));
        // m[13] = (fr_add(m[13], m[17]));
        // m[17] = (fr_sub(1, proof[97]));
        update(m, proof, absorbing, uint256(44904608418248980538468526693625107873620046362741380801655990689085847634529));
        // m[17] = (fr_mul(m[17], m[12]));
        // m[14] = (fr_mul(proof[100], proof[100]));
        // m[14] = (fr_sub(m[14], proof[100]));
        // m[14] = (fr_mul(m[14], m[19]));
        // m[15] = (fr_sub(proof[100], proof[99]));
        // m[15] = (fr_mul(m[12], m[15]));
        // m[16] = (fr_mul(m[5], m[1]));
        // m[21] = (fr_mul(proof[91], m[1]));
        update(m, proof, absorbing, uint256(45371111122442633822644854137212312036027785087345482408764708148759562598273));
        // m[21] = (fr_add(m[21], m[2]));
        // m[21] = (fr_add(proof[67], m[21]));
        // m[21] = (fr_mul(proof[98], m[21]));
        // m[20] = (fr_add(m[16], m[2]));
        // m[20] = (fr_add(proof[67], m[20]));
        // m[20] = (fr_mul(proof[97], m[20]));
        update(m, proof, absorbing, uint256(2483329521785241698034788896230326133243504537454947124116));
        m[22] = (fr_mul(m[16], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[23] = (fr_mul(proof[92], m[1]));
        // m[23] = (fr_add(m[23], m[2]));
        // m[23] = (fr_add(proof[68], m[23]));
        // m[21] = (fr_mul(m[21], m[23]));
        // m[23] = (fr_add(m[22], m[2]));
        // m[23] = (fr_add(proof[68], m[23]));
        // m[20] = (fr_mul(m[20], m[23]));
        update(m, proof, absorbing, uint256(10720760286727560125415118128201862132536427687240175578004237265303));
        m[23] = (fr_mul(m[22], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[22] = (fr_mul(proof[93], m[1]));
        // m[22] = (fr_add(m[22], m[2]));
        // m[22] = (fr_add(proof[69], m[22]));
        // m[21] = (fr_mul(m[21], m[22]));
        // m[22] = (fr_add(m[23], m[2]));
        // m[22] = (fr_add(proof[69], m[22]));
        // m[20] = (fr_mul(m[20], m[22]));
        update(m, proof, absorbing, uint256(10694435427680378616267460762540985235025864389817615027622091106710));
        m[22] = (fr_mul(m[23], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[21] = (fr_sub(m[21], m[20]));
        // m[20] = (fr_add(m[19], m[18]));
        // m[20] = (fr_sub(1, m[20]));
        // m[21] = (fr_mul(m[20], m[21]));
        update(m, proof, absorbing, uint256(134642333739314259713865750595987515797));
        m[22] = (fr_mul(11166246659983828508719468090013646171463329086121580628794302409516816350802, m[16]));
        // m[23] = (fr_mul(proof[94], m[1]));
        // m[23] = (fr_add(m[23], m[2]));
        // m[23] = (fr_add(proof[70], m[23]));
        // m[23] = (fr_mul(proof[101], m[23]));
        // m[18] = (fr_add(m[22], m[2]));
        // m[18] = (fr_add(proof[70], m[18]));
        // m[18] = (fr_mul(proof[100], m[18]));
        update(m, proof, absorbing, uint256(10720766714479737161376220644500027506520290944006216113955695020434));
        m[22] = (fr_mul(m[22], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[16] = (fr_mul(proof[95], m[1]));
        // m[16] = (fr_add(m[16], m[2]));
        // m[16] = (fr_add(proof[71], m[16]));
        // m[23] = (fr_mul(m[23], m[16]));
        // m[16] = (fr_add(m[22], m[2]));
        // m[16] = (fr_add(proof[71], m[16]));
        // m[18] = (fr_mul(m[18], m[16]));
        update(m, proof, absorbing, uint256(10536473417892935489459311535981362361707222061097108273073245595024));
        m[22] = (fr_mul(m[22], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[16] = (fr_mul(proof[96], m[1]));
        // m[16] = (fr_add(m[16], m[2]));
        // m[16] = (fr_add(proof[66], m[16]));
        // m[23] = (fr_mul(m[23], m[16]));
        // m[16] = (fr_add(m[22], m[2]));
        // m[16] = (fr_add(proof[66], m[16]));
        // m[18] = (fr_mul(m[18], m[16]));
        update(m, proof, absorbing, uint256(10536476631769024007439861748782687726429960639264100802337178592656));
        m[22] = (fr_mul(m[22], 4131629893567559867359510883348571134090853742863529169391034518566172092834));
        // m[22] = (fr_sub(m[23], m[18]));
        // m[22] = (fr_mul(m[20], m[22]));
        // m[23] = (fr_add(proof[104], m[1]));
        // m[23] = (fr_mul(m[23], proof[103]));
        // m[18] = (fr_add(proof[106], m[2]));
        // m[23] = (fr_mul(m[18], m[23]));
        // m[18] = (fr_mul(proof[82], proof[67]));
        // m[0] = (fr_mul(m[0], 0));
        update(m, proof, absorbing, uint256(45929517777840048282978186135535496150534469229204905991546542240975215853824));
        // m[18] = (fr_add(m[0], m[18]));
        // m[16] = (fr_add(m[0], proof[83]));
        // m[24] = (fr_sub(1, proof[102]));
        // m[24] = (fr_mul(m[24], m[12]));
        // m[25] = (fr_mul(proof[102], proof[102]));
        // m[25] = (fr_sub(m[25], proof[102]));
        // m[25] = (fr_mul(m[25], m[19]));
        // m[18] = (fr_add(m[18], m[1]));
        update(m, proof, absorbing, uint256(45469820060504390239715824885569983354150089333857588878118465267008237151617));
        // m[18] = (fr_mul(m[18], proof[102]));
        // m[16] = (fr_add(m[16], m[2]));
        // m[18] = (fr_mul(m[16], m[18]));
        // m[23] = (fr_sub(m[23], m[18]));
        // m[23] = (fr_mul(m[20], m[23]));
        // m[18] = (fr_sub(proof[104], proof[106]));
        // m[27] = (fr_mul(m[18], m[12]));
        // m[26] = (fr_sub(proof[104], proof[105]));
        update(m, proof, absorbing, uint256(45484195211907154953399853301192819889750839339510878412064805092663950364777));
        // m[18] = (fr_mul(m[26], m[18]));
        // m[18] = (fr_mul(m[20], m[18]));
        // m[26] = (fr_add(proof[109], m[1]));
        // m[26] = (fr_mul(m[26], proof[108]));
        // m[29] = (fr_add(proof[111], m[2]));
        // m[29] = (fr_mul(m[29], m[26]));
        // m[28] = (fr_mul(proof[82], proof[68]));
        // m[28] = (fr_add(m[0], m[28]));
        update(m, proof, absorbing, uint256(45484313727888663858547349333577677764540501519077813682095336016536045814172));
        // m[26] = (fr_sub(1, proof[107]));
        // m[26] = (fr_mul(m[26], m[12]));
        // m[31] = (fr_mul(proof[107], proof[107]));
        // m[31] = (fr_sub(m[31], proof[107]));
        // m[31] = (fr_mul(m[31], m[19]));
        // m[28] = (fr_add(m[28], m[1]));
        // m[28] = (fr_mul(m[28], proof[107]));
        // m[28] = (fr_mul(m[16], m[28]));
        update(m, proof, absorbing, uint256(46379752149440342204980419326570497728925854721608335184053389669647338381724));
        // m[29] = (fr_sub(m[29], m[28]));
        // m[29] = (fr_mul(m[20], m[29]));
        // m[28] = (fr_sub(proof[109], proof[111]));
        // m[30] = (fr_mul(m[28], m[12]));
        // m[33] = (fr_sub(proof[109], proof[110]));
        // m[33] = (fr_mul(m[33], m[28]));
        // m[33] = (fr_mul(m[20], m[33]));
        // m[32] = (fr_add(proof[114], m[1]));
        update(m, proof, absorbing, uint256(46721148353600689175294074179742212627929234943224076693777042766922745439617));
        // m[32] = (fr_mul(m[32], proof[113]));
        // m[28] = (fr_add(proof[116], m[2]));
        // m[32] = (fr_mul(m[28], m[32]));
        // m[28] = (fr_mul(proof[82], proof[69]));
        // m[28] = (fr_add(m[0], m[28]));
        // m[35] = (fr_sub(1, proof[112]));
        // m[35] = (fr_mul(m[35], m[12]));
        // m[34] = (fr_mul(proof[112], proof[112]));
        update(m, proof, absorbing, uint256(47067483727720734921431934980199772007357729479367277496419501716065879908464));
        // m[34] = (fr_sub(m[34], proof[112]));
        // m[34] = (fr_mul(m[34], m[19]));
        // m[28] = (fr_add(m[28], m[1]));
        // m[28] = (fr_mul(m[28], proof[112]));
        // m[28] = (fr_mul(m[16], m[28]));
        // m[32] = (fr_sub(m[32], m[28]));
        // m[32] = (fr_mul(m[20], m[32]));
        // m[28] = (fr_sub(proof[114], proof[116]));
        update(m, proof, absorbing, uint256(47286600343940925217286427716748734819925326956121834879340530729707995980916));
        // m[36] = (fr_mul(m[28], m[12]));
        // m[37] = (fr_sub(proof[114], proof[115]));
        // m[37] = (fr_mul(m[37], m[28]));
        // m[37] = (fr_mul(m[20], m[37]));
        // m[28] = (fr_add(proof[119], m[1]));
        // m[28] = (fr_mul(m[28], proof[118]));
        // m[38] = (fr_add(proof[121], m[2]));
        // m[38] = (fr_mul(m[38], m[28]));
        update(m, proof, absorbing, uint256(47519748992236723820921505743052969419855017603891912539328327024240610987420));
        // m[28] = (fr_mul(proof[82], proof[70]));
        // m[28] = (fr_add(m[0], m[28]));
        // m[39] = (fr_sub(1, proof[117]));
        // m[39] = (fr_mul(m[39], m[12]));
        // m[41] = (fr_mul(proof[117], proof[117]));
        // m[41] = (fr_sub(m[41], proof[117]));
        // m[41] = (fr_mul(m[41], m[19]));
        // m[40] = (fr_add(m[28], m[1]));
        update(m, proof, absorbing, uint256(46610559353300967231009871500769184943770895781313439982116265171373598914945));
        // m[40] = (fr_mul(m[40], proof[117]));
        // m[40] = (fr_mul(m[16], m[40]));
        // m[40] = (fr_sub(m[38], m[40]));
        // m[40] = (fr_mul(m[20], m[40]));
        // m[38] = (fr_sub(proof[119], proof[121]));
        // m[28] = (fr_mul(m[38], m[12]));
        // m[16] = (fr_sub(proof[119], proof[120]));
        // m[38] = (fr_mul(m[16], m[38]));
        update(m, proof, absorbing, uint256(47972219960988743879309724686710515347142963969232348875561794015153699627430));
        // m[38] = (fr_mul(m[20], m[38]));
        // m[16] = (fr_add(proof[124], m[1]));
        // m[16] = (fr_mul(m[16], proof[123]));
        // m[42] = (fr_add(proof[126], m[2]));
        // m[42] = (fr_mul(m[42], m[16]));
        // m[43] = (fr_mul(proof[84], proof[67]));
        // m[43] = (fr_add(m[0], m[43]));
        // m[16] = (fr_add(m[0], proof[85]));
        update(m, proof, absorbing, uint256(47745795688990920509636565064534348231931823715931498272894782207083097292885));
        // m[45] = (fr_sub(1, proof[122]));
        // m[45] = (fr_mul(m[45], m[12]));
        // m[44] = (fr_mul(proof[122], proof[122]));
        // m[44] = (fr_sub(m[44], proof[122]));
        // m[44] = (fr_mul(m[44], m[19]));
        // m[43] = (fr_add(m[43], m[1]));
        // m[43] = (fr_mul(m[43], proof[122]));
        // m[16] = (fr_add(m[16], m[2]));
        update(m, proof, absorbing, uint256(48528238585110352006164335500323376147489236111590864415213545527111099818370));
        // m[43] = (fr_mul(m[16], m[43]));
        // m[42] = (fr_sub(m[42], m[43]));
        // m[42] = (fr_mul(m[20], m[42]));
        // m[43] = (fr_sub(proof[124], proof[126]));
        // m[16] = (fr_mul(m[43], m[12]));
        // m[46] = (fr_sub(proof[124], proof[125]));
        // m[46] = (fr_mul(m[46], m[43]));
        // m[46] = (fr_mul(m[20], m[46]));
        update(m, proof, absorbing, uint256(48311131671236108761125450968247818771188827121608198305913548284106522962350));
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
        // m[51] = (fr_mul(m[51], m[19]));
        // m[50] = (fr_add(m[43], m[1]));
        // m[50] = (fr_mul(m[50], proof[127]));
        // m[48] = (fr_add(m[48], m[2]));
        // m[48] = (fr_mul(m[48], m[50]));
        update(m, proof, absorbing, uint256(48990055623849185168010971127228524498211880658572421146304863777202516222386));
        // m[47] = (fr_sub(m[47], m[48]));
        // m[47] = (fr_mul(m[20], m[47]));
        // m[50] = (fr_sub(proof[129], proof[131]));
        // m[43] = (fr_mul(m[50], m[12]));
        // m[48] = (fr_sub(proof[129], proof[130]));
        // m[48] = (fr_mul(m[48], m[50]));
        // m[48] = (fr_mul(m[20], m[48]));
        // m[50] = (fr_add(proof[134], m[1]));
        update(m, proof, absorbing, uint256(48756805174766711151914389624871838632642343870230222325421505947581091745153));
        // m[50] = (fr_mul(m[50], proof[133]));
        // m[52] = (fr_add(proof[136], m[2]));
        // m[52] = (fr_mul(m[52], m[50]));
        // m[50] = (fr_mul(proof[88], proof[67]));
        // m[50] = (fr_add(m[0], m[50]));
        // m[0] = (fr_add(m[0], proof[89]));
        // m[53] = (fr_sub(1, proof[132]));
        // m[53] = (fr_mul(m[53], m[12]));
        update(m, proof, absorbing, uint256(49103140549044789500076768353945308292159296378750414828715051685461646863244));
        // m[55] = (fr_mul(proof[132], proof[132]));
        // m[55] = (fr_sub(m[55], proof[132]));
        // m[55] = (fr_mul(m[55], m[19]));
        // m[19] = (fr_add(m[50], m[1]));
        // m[19] = (fr_mul(m[19], proof[132]));
        // m[2] = (fr_add(m[0], m[2]));
        // m[2] = (fr_mul(m[2], m[19]));
        // m[2] = (fr_sub(m[52], m[2]));
        update(m, proof, absorbing, uint256(49664362928102066251263284568936861866289052793563288812272250982305744251266));
        // m[2] = (fr_mul(m[20], m[2]));
        // m[0] = (fr_sub(proof[134], proof[136]));
        // m[19] = (fr_mul(m[0], m[12]));
        // m[50] = (fr_sub(proof[134], proof[135]));
        // m[0] = (fr_mul(m[50], m[0]));
        // m[20] = (fr_mul(m[20], m[0]));
        // m[0] = (fr_mul(m[3], 0));
        // m[0] = (fr_add(m[0], m[13]));
        update(m, proof, absorbing, uint256(43674979080763869910517638915453037477111029583553810978908972882401943814541));
        // m[0] = (fr_mul(m[3], m[0]));
        // m[52] = (fr_add(m[0], m[17]));
        // m[52] = (fr_mul(m[3], m[52]));
        // m[52] = (fr_add(m[52], m[14]));
        // m[52] = (fr_mul(m[3], m[52]));
        // m[52] = (fr_add(m[52], m[15]));
        // m[52] = (fr_mul(m[3], m[52]));
        // m[21] = (fr_add(m[52], m[21]));
        update(m, proof, absorbing, uint256(43448587944544771922651227772687244862959154999525414165889899922804103932309));
        // m[21] = (fr_mul(m[3], m[21]));
        // m[21] = (fr_add(m[21], m[22]));
        // m[21] = (fr_mul(m[3], m[21]));
        // m[21] = (fr_add(m[21], m[24]));
        // m[21] = (fr_mul(m[3], m[21]));
        // m[21] = (fr_add(m[21], m[25]));
        // m[21] = (fr_mul(m[3], m[21]));
        // m[52] = (fr_add(m[21], m[23]));
        update(m, proof, absorbing, uint256(45823230964949697733936635166890984990944401226357092531180039217428266691479));
        // m[52] = (fr_mul(m[3], m[52]));
        // m[52] = (fr_add(m[52], m[27]));
        // m[52] = (fr_mul(m[3], m[52]));
        // m[52] = (fr_add(m[52], m[18]));
        // m[52] = (fr_mul(m[3], m[52]));
        // m[52] = (fr_add(m[52], m[26]));
        // m[52] = (fr_mul(m[3], m[52]));
        // m[52] = (fr_add(m[52], m[31]));
        update(m, proof, absorbing, uint256(49328656378044628847665331466699926212430443618130064354819694847726899915167));
        // m[52] = (fr_mul(m[3], m[52]));
        // m[52] = (fr_add(m[52], m[29]));
        // m[52] = (fr_mul(m[3], m[52]));
        // m[52] = (fr_add(m[52], m[30]));
        // m[52] = (fr_mul(m[3], m[52]));
        // m[52] = (fr_add(m[52], m[33]));
        // m[52] = (fr_mul(m[3], m[52]));
        // m[35] = (fr_add(m[52], m[35]));
        update(m, proof, absorbing, uint256(49328656378044628860219534937473287744185410867596658748714028234352083036579));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[34]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[32]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[36]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[37]));
        update(m, proof, absorbing, uint256(47406326312799021523868456853474945245531070423495429081816780444259464988581));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[39]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[41]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[40]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[28]));
        update(m, proof, absorbing, uint256(47406326312799021555253965530408349067772558841822207333572716109760389662620));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[38]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[45]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[44]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[42]));
        update(m, proof, absorbing, uint256(47406326312799021548976863795021668305297898886298294771397646071318266202026));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[16]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[46]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[49]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[51]));
        update(m, proof, absorbing, uint256(47406326312799021410880625616514691501250813942650572080701434620909822887859));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[47]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[43]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[48]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[53]));
        update(m, proof, absorbing, uint256(47406326312799021605470779413501795179139438961325415589465882832925878601653));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[55]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[2]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[19]));
        // m[35] = (fr_mul(m[3], m[35]));
        // m[35] = (fr_add(m[35], m[20]));
        update(m, proof, absorbing, uint256(47406326312799021655687593296595241275874177303228269915751411905798081038228));
        // m[35] = (fr_div(m[35], m[11]));
        // m[52] = (fr_mul(m[10], m[10]));
        // m[24] = (fr_mul(m[52], m[10]));
        // (m[26], m[27]) = (ecc_mul(proof[137], proof[138], m[24]));
        // (m[40], m[41]) = (ecc_mul(proof[139], proof[140], m[52]));
        // (m[26], m[27]) = (ecc_add(m[26], m[27], m[40], m[41]));
        // (m[40], m[41]) = (ecc_mul(proof[141], proof[142], m[10]));
        // (m[26], m[27]) = (ecc_add(m[26], m[27], m[40], m[41]));
        update(m, proof, absorbing, uint256(47413834766236397396739793479136558862774377832551849724059814721578091361704));
        // (m[26], m[27]) = (ecc_add(m[26], m[27], proof[143], proof[144]));
        // m[24] = (fr_mul(m[7], m[10]));
        // m[40] = (fr_mul(proof[99], m[10]));
        // m[15] = (fr_mul(proof[105], m[8]));
        // m[53] = (fr_mul(m[8], m[8]));
        // m[15] = (fr_add(m[15], proof[110]));
        // m[15] = (fr_mul(m[15], m[8]));
        // m[44] = (fr_mul(m[53], m[8]));
        update(m, proof, absorbing, uint256(104270842284726807087410566651053723480679458903135639443502345031108038454152));
        // m[15] = (fr_add(m[15], proof[115]));
        // m[15] = (fr_mul(m[15], m[8]));
        // m[16] = (fr_mul(m[44], m[8]));
        // m[15] = (fr_add(m[15], proof[120]));
        // m[15] = (fr_mul(m[15], m[8]));
        // m[41] = (fr_mul(m[16], m[8]));
        // m[15] = (fr_add(m[15], proof[125]));
        // m[15] = (fr_mul(m[15], m[8]));
        update(m, proof, absorbing, uint256(45130784738929663777030572506063643203589612128975618657406524408546051694472));
        // m[13] = (fr_mul(m[41], m[8]));
        // m[15] = (fr_add(m[15], proof[130]));
        // m[15] = (fr_mul(m[15], m[8]));
        // m[24] = (fr_mul(m[24], m[10]));
        // m[40] = (fr_add(m[40], m[15]));
        // m[40] = (fr_add(m[40], proof[135]));
        // m[40] = (fr_mul(m[40], m[10]));
        // m[15] = (fr_mul(m[6], m[10]));
        update(m, proof, absorbing, uint256(44919129449868224913803297770121091079892356001876551820326503565349648010634));
        // m[6] = (fr_mul(m[13], m[10]));
        // m[50] = (fr_mul(m[41], m[10]));
        // m[34] = (fr_mul(m[16], m[10]));
        // m[42] = (fr_mul(m[44], m[10]));
        // m[51] = (fr_mul(m[53], m[10]));
        // m[43] = (fr_mul(m[8], m[10]));
        // m[21] = (fr_mul(proof[66], m[8]));
        // m[21] = (fr_add(m[21], proof[67]));
        update(m, proof, absorbing, uint256(44127195521896840576143311550406491844973184073664054086469687789637431929411));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[21] = (fr_add(m[21], proof[68]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[21] = (fr_add(m[21], proof[69]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[21] = (fr_add(m[21], proof[70]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[21] = (fr_add(m[21], proof[71]));
        update(m, proof, absorbing, uint256(45823479077338873399614292376932300897052500236256120515862333231211385137735));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[23] = (fr_mul(m[13], m[8]));
        // m[21] = (fr_add(m[21], proof[97]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[7] = (fr_mul(m[23], m[8]));
        // m[21] = (fr_add(m[21], proof[100]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[30] = (fr_mul(m[7], m[8]));
        update(m, proof, absorbing, uint256(45823479077394796877334700824892491219484346314099858385334938340808392118152));
        // m[21] = (fr_add(m[21], proof[102]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[48] = (fr_mul(m[30], m[8]));
        // m[21] = (fr_add(m[21], proof[104]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[20] = (fr_mul(m[48], m[8]));
        // m[21] = (fr_add(m[21], proof[106]));
        // m[21] = (fr_mul(m[21], m[8]));
        update(m, proof, absorbing, uint256(45809336482439405894353206473873920563807104234347838647108602681906185579400));
        // m[54] = (fr_mul(m[20], m[8]));
        // m[21] = (fr_add(m[21], proof[107]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[18] = (fr_mul(m[54], m[8]));
        // m[21] = (fr_add(m[21], proof[109]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[36] = (fr_mul(m[18], m[8]));
        // m[21] = (fr_add(m[21], proof[111]));
        update(m, proof, absorbing, uint256(49555046274658127767373609509066072560230533645523404853507958541694903200367));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[31] = (fr_mul(m[36], m[8]));
        // m[21] = (fr_add(m[21], proof[112]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[17] = (fr_mul(m[31], m[8]));
        // m[21] = (fr_add(m[21], proof[114]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[1] = (fr_mul(m[17], m[8]));
        update(m, proof, absorbing, uint256(45823479077605495379821851133763526765074802039780653036585236584464959611784));
        // m[21] = (fr_add(m[21], proof[116]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[22] = (fr_mul(m[1], m[8]));
        // m[21] = (fr_add(m[21], proof[117]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[25] = (fr_mul(m[22], m[8]));
        // m[21] = (fr_add(m[21], proof[119]));
        // m[21] = (fr_mul(m[21], m[8]));
        update(m, proof, absorbing, uint256(45809336859878659234302762362585768255989806856104418871933082166146412522376));
        // m[33] = (fr_mul(m[25], m[8]));
        // m[21] = (fr_add(m[21], proof[121]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[38] = (fr_mul(m[33], m[8]));
        // m[21] = (fr_add(m[21], proof[122]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[45] = (fr_mul(m[38], m[8]));
        // m[21] = (fr_add(m[21], proof[124]));
        update(m, proof, absorbing, uint256(47180472837059447221930956311068284834052081788840397176961857013535310555772));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[37] = (fr_mul(m[45], m[8]));
        // m[21] = (fr_add(m[21], proof[126]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[19] = (fr_mul(m[37], m[8]));
        // m[21] = (fr_add(m[21], proof[127]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[3] = (fr_mul(m[19], m[8]));
        update(m, proof, absorbing, uint256(45823479077763492742209483596096386484551275541424236439364215280655905269640));
        // m[21] = (fr_add(m[21], proof[129]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[2] = (fr_mul(m[3], m[8]));
        // m[21] = (fr_add(m[21], proof[131]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[32] = (fr_mul(m[2], m[8]));
        // m[21] = (fr_add(m[21], proof[132]));
        // m[21] = (fr_mul(m[21], m[8]));
        update(m, proof, absorbing, uint256(45809337210357965907138481546565369910184879228682220230104609961578630949768));
        // m[12] = (fr_mul(m[32], m[8]));
        // m[21] = (fr_add(m[21], proof[134]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[46] = (fr_mul(m[12], m[8]));
        // m[21] = (fr_add(m[21], proof[136]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[11] = (fr_mul(m[46], m[8]));
        // m[21] = (fr_add(m[21], proof[73]));
        update(m, proof, absorbing, uint256(44805927006446153832466351116690138479827178794892140496739716441441342794313));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[28] = (fr_mul(m[11], m[8]));
        // m[21] = (fr_add(m[21], proof[74]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[39] = (fr_mul(m[28], m[8]));
        // m[21] = (fr_add(m[21], proof[75]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[0] = (fr_mul(m[39], m[8]));
        update(m, proof, absorbing, uint256(45823479077526430814168220238689248927640431897953691376337906240730382159752));
        // m[21] = (fr_add(m[21], proof[76]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[55] = (fr_mul(m[0], m[8]));
        // m[21] = (fr_add(m[21], proof[77]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[47] = (fr_mul(m[55], m[8]));
        // m[21] = (fr_add(m[21], proof[78]));
        // m[21] = (fr_mul(m[21], m[8]));
        update(m, proof, absorbing, uint256(45809335781480792548479459239010623777474292921080012372506171392120524319624));
        // m[49] = (fr_mul(m[47], m[8]));
        // m[21] = (fr_add(m[21], proof[79]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[29] = (fr_mul(m[49], m[8]));
        // m[21] = (fr_add(m[21], proof[80]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[14] = (fr_mul(m[29], m[8]));
        // m[21] = (fr_add(m[21], proof[81]));
        update(m, proof, absorbing, uint256(48990027908231771296592627194833539060634973547384602303427958226979245206097));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[56] = (fr_mul(m[14], m[8]));
        // m[21] = (fr_add(m[21], proof[82]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[57] = (fr_mul(m[56], m[8]));
        // m[21] = (fr_add(m[21], proof[83]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[59] = (fr_mul(m[57], m[8]));
        update(m, proof, absorbing, uint256(45823479078263626497476386111208341471851884978587020765159161698922288608136));
        // m[21] = (fr_add(m[21], proof[84]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[58] = (fr_mul(m[59], m[8]));
        // m[21] = (fr_add(m[21], proof[85]));
        // m[21] = (fr_mul(m[21], m[8]));
        // m[60] = (fr_mul(m[58], m[8]));
        // m[61] = (fr_add(m[21], proof[86]));
        // m[61] = (fr_mul(m[61], m[8]));
        update(m, proof, absorbing, uint256(45809335997160365885703011691878595634569250506782911718835469580946147081096));
        // m[21] = (fr_mul(m[60], m[8]));
        // m[61] = (fr_add(m[61], proof[87]));
        // m[61] = (fr_mul(m[61], m[8]));
        // m[62] = (fr_mul(m[21], m[8]));
        // m[61] = (fr_add(m[61], proof[88]));
        // m[61] = (fr_mul(m[61], m[8]));
        // m[63] = (fr_mul(m[62], m[8]));
        // m[61] = (fr_add(m[61], proof[89]));
        update(m, proof, absorbing, uint256(45824017414607174654828987064588487077237971871373326323362214987779329718873));
        // m[61] = (fr_mul(m[61], m[8]));
        // m[64] = (fr_mul(m[63], m[8]));
        // m[61] = (fr_add(m[61], proof[91]));
        // m[61] = (fr_mul(m[61], m[8]));
        // m[65] = (fr_mul(m[64], m[8]));
        // m[61] = (fr_add(m[61], proof[92]));
        // m[61] = (fr_mul(m[61], m[8]));
        // m[67] = (fr_mul(m[65], m[8]));
        update(m, proof, absorbing, uint256(50347159704014815689823303479324720568959828458097085175787911348495485731720));
        // m[61] = (fr_add(m[61], proof[93]));
        // m[61] = (fr_mul(m[61], m[8]));
        // m[66] = (fr_mul(m[67], m[8]));
        // m[61] = (fr_add(m[61], proof[94]));
        // m[61] = (fr_mul(m[61], m[8]));
        // m[69] = (fr_mul(m[66], m[8]));
        // m[61] = (fr_add(m[61], proof[95]));
        // m[61] = (fr_mul(m[61], m[8]));
        update(m, proof, absorbing, uint256(50333016866393544490673164656129320444717341258497430322985333988360794897288));
        // m[68] = (fr_mul(m[69], m[8]));
        // m[61] = (fr_add(m[61], proof[96]));
        // m[61] = (fr_mul(m[61], m[8]));
        // m[70] = (fr_mul(m[9], m[9]));
        // m[71] = (fr_mul(m[70], m[9]));
        // m[72] = (fr_mul(m[68], m[8]));
        // m[35] = (fr_add(m[61], m[35]));
        // m[35] = (fr_mul(m[35], m[8]));
        update(m, proof, absorbing, uint256(51138817616894797004857635390920249725017725043342314344290192035394349909896));
        // m[61] = (fr_mul(m[71], m[8]));
        // m[73] = (fr_mul(m[70], m[8]));
        // m[9] = (fr_mul(m[9], m[8]));
        // m[24] = (fr_mul(m[24], m[10]));
        // m[52] = (fr_add(m[52], m[64]));
        // m[52] = (fr_mul(m[52], m[10]));
        // m[35] = (fr_add(m[40], m[35]));
        // m[35] = (fr_add(m[35], proof[90]));
        update(m, proof, absorbing, uint256(50347297739178726654167894174486053249496479101822496217234958345435410286170));
        // m[35] = (fr_mul(m[35], m[10]));
        // m[40] = (fr_mul(m[15], m[10]));
        // m[15] = (fr_add(m[6], m[21]));
        // m[15] = (fr_mul(m[15], m[10]));
        // m[59] = (fr_add(m[50], m[59]));
        // m[59] = (fr_mul(m[59], m[10]));
        // m[21] = (fr_add(m[34], m[14]));
        // m[21] = (fr_mul(m[21], m[10]));
        update(m, proof, absorbing, uint256(47406767350701416386589621031077519186770473404527383567431052610166949096330));
        // m[70] = (fr_add(m[42], m[47]));
        // m[70] = (fr_mul(m[70], m[10]));
        // m[39] = (fr_add(m[51], m[39]));
        // m[39] = (fr_mul(m[39], m[10]));
        // m[46] = (fr_add(m[43], m[46]));
        // m[46] = (fr_mul(m[46], m[10]));
        // m[2] = (fr_add(m[10], m[2]));
        // m[2] = (fr_mul(m[2], m[10]));
        update(m, proof, absorbing, uint256(51350467622043670913532438202424175268010009213569242624640546406899685197194));
        // m[5] = (fr_mul(m[5], m[10]));
        // m[72] = (fr_mul(m[72], m[10]));
        // m[68] = (fr_mul(m[68], m[10]));
        // m[69] = (fr_mul(m[69], m[10]));
        // m[66] = (fr_mul(m[66], m[10]));
        // m[67] = (fr_mul(m[67], m[10]));
        // m[65] = (fr_mul(m[65], m[10]));
        // m[63] = (fr_mul(m[63], m[10]));
        update(m, proof, absorbing, uint256(44014006882388792564573648443116674607481270504082774084680819196806216777610));
        // m[62] = (fr_mul(m[62], m[10]));
        // m[60] = (fr_mul(m[60], m[10]));
        // m[47] = (fr_mul(m[58], m[10]));
        // m[57] = (fr_mul(m[57], m[10]));
        // m[56] = (fr_mul(m[56], m[10]));
        // m[58] = (fr_mul(m[29], m[10]));
        // m[49] = (fr_mul(m[49], m[10]));
        // m[55] = (fr_mul(m[55], m[10]));
        update(m, proof, absorbing, uint256(50460251773467897281517814403796526982644583991844774156614305312379748970378));
        // m[0] = (fr_mul(m[0], m[10]));
        // m[28] = (fr_mul(m[28], m[10]));
        // m[11] = (fr_mul(m[11], m[10]));
        // m[12] = (fr_mul(m[12], m[10]));
        // m[32] = (fr_mul(m[32], m[10]));
        // m[3] = (fr_mul(m[3], m[10]));
        // m[19] = (fr_mul(m[19], m[10]));
        // m[37] = (fr_mul(m[37], m[10]));
        update(m, proof, absorbing, uint256(43448546803037665054217643414636402340904846638586140611840826527166648765322));
        // m[45] = (fr_mul(m[45], m[10]));
        // m[38] = (fr_mul(m[38], m[10]));
        // m[33] = (fr_mul(m[33], m[10]));
        // m[25] = (fr_mul(m[25], m[10]));
        // m[22] = (fr_mul(m[22], m[10]));
        // m[1] = (fr_mul(m[1], m[10]));
        // m[17] = (fr_mul(m[17], m[10]));
        // m[31] = (fr_mul(m[31], m[10]));
        update(m, proof, absorbing, uint256(48537687507033935942225563561323116106977037178722251058666797764056770887562));
        // m[36] = (fr_mul(m[36], m[10]));
        // m[18] = (fr_mul(m[18], m[10]));
        // m[54] = (fr_mul(m[54], m[10]));
        // m[20] = (fr_mul(m[20], m[10]));
        // m[48] = (fr_mul(m[48], m[10]));
        // m[29] = (fr_mul(m[30], m[10]));
        // m[71] = (fr_mul(m[7], m[10]));
        // m[64] = (fr_mul(m[23], m[10]));
        update(m, proof, absorbing, uint256(47519859365760718602501599421680264374892746122014076559548736693131619020682));
        // m[61] = (fr_mul(m[61], m[10]));
        // m[73] = (fr_mul(m[73], m[10]));
        // m[9] = (fr_mul(m[9], m[10]));
        // m[14] = (fr_mul(proof[72], m[8]));
        // m[14] = (fr_add(m[14], proof[98]));
        // m[14] = (fr_mul(m[14], m[8]));
        // m[14] = (fr_add(m[14], proof[101]));
        // m[14] = (fr_mul(m[14], m[8]));
        update(m, proof, absorbing, uint256(50347159758171693831375894096326524920056230446021569042716045943872108305800));
        // m[14] = (fr_add(m[14], proof[103]));
        // m[14] = (fr_mul(m[14], m[8]));
        // m[14] = (fr_add(m[14], proof[108]));
        // m[14] = (fr_mul(m[14], m[8]));
        // m[14] = (fr_add(m[14], proof[113]));
        // m[14] = (fr_mul(m[14], m[8]));
        // m[14] = (fr_add(m[14], proof[118]));
        // m[14] = (fr_mul(m[14], m[8]));
        update(m, proof, absorbing, uint256(45017692399745462306195712170014936846104519871164134842467020538607293111688));
        // m[14] = (fr_add(m[14], proof[123]));
        // m[14] = (fr_mul(m[14], m[8]));
        // m[14] = (fr_add(m[14], proof[128]));
        // m[14] = (fr_mul(m[14], m[8]));
        // (m[74], m[75]) = (ecc_mul(proof[137], proof[138], m[24]));
        // m[24] = (fr_add(m[52], m[7]));
        // (m[76], m[77]) = (ecc_mul(proof[38], proof[39], m[24]));
        // (m[76], m[77]) = (ecc_add(m[74], m[75], m[76], m[77]));
        update(m, proof, absorbing, uint256(45017692938944395649208508092585271333305302285708090431596165622820738930124));
        // m[35] = (fr_add(m[35], m[14]));
        // m[35] = (fr_add(m[35], proof[133]));
        // (m[74], m[75]) = (ecc_mul(proof[139], proof[140], m[40]));
        // (m[76], m[77]) = (ecc_add(m[76], m[77], m[74], m[75]));
        // (m[14], m[15]) = (ecc_mul(proof[10], proof[11], m[15]));
        // (m[14], m[15]) = (ecc_add(m[76], m[77], m[14], m[15]));
        // (m[76], m[77]) = (ecc_mul(proof[14], proof[15], m[59]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[76], m[77]));
        update(m, proof, absorbing, uint256(47392632681888107249554190629166153739897396341746124515167400426559295135180));
        // (m[76], m[77]) = (ecc_mul(proof[18], proof[19], m[21]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[22], proof[23], m[70]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[26], proof[27], m[39]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[30], proof[31], m[46]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[76], m[77]));
        update(m, proof, absorbing, uint256(109933483776119431518241853763244896947196169461039807296793756050406752329164));
        // (m[76], m[77]) = (ecc_mul(proof[34], proof[35], m[2]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[141], proof[142], m[5]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[76], m[77]));
        update(m, proof, absorbing, uint256(323066120394377196811161405708472622540));
        (m[76], m[77]) = (ecc_mul(instances[0], instances[1], m[72]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[0], proof[1], m[68]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[2], proof[3], m[69]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[76], m[77]));
        // (m[76], m[77]) = (ecc_mul(proof[4], proof[5], m[66]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[76], m[77]));
        // (m[66], m[67]) = (ecc_mul(proof[6], proof[7], m[67]));
        update(m, proof, absorbing, uint256(102913746658215555302278993011537116165682082087322100810446638717705399307715));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[66], m[67]));
        // m[24] = (fr_add(m[65], m[30]));
        // (m[66], m[67]) = (ecc_mul(proof[8], proof[9], m[24]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[66], m[67]));
        // m[24] = (fr_add(m[63], m[23]));
        // (m[66], m[67]) = (ecc_mul(proof[40], proof[41], m[24]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[66], m[67]));
        // m[24] = (fr_add(m[62], m[13]));
        update(m, proof, absorbing, uint256(102913746373765207288544501368486692789821547637631106113531123626008656706957));
        // (m[66], m[67]) = (ecc_mul(proof[42], proof[43], m[24]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[66], m[67]));
        // (m[66], m[67]) = (ecc_mul(proof[12], proof[13], m[60]));
        // (m[14], m[15]) = (ecc_add(m[14], m[15], m[66], m[67]));
        // m[24] = (fr_add(m[47], m[41]));
        // (m[40], m[41]) = (ecc_mul(proof[44], proof[45], m[24]));
        // (m[40], m[41]) = (ecc_add(m[14], m[15], m[40], m[41]));
        // (m[46], m[47]) = (ecc_mul(proof[16], proof[17], m[57]));
        update(m, proof, absorbing, uint256(108803033019365751432989934942047020951532721017037967457994504575771367711161));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[46], m[47]));
        // m[24] = (fr_add(m[56], m[16]));
        // (m[56], m[57]) = (ecc_mul(proof[46], proof[47], m[24]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[56], m[57]));
        // (m[56], m[57]) = (ecc_mul(proof[20], proof[21], m[58]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[56], m[57]));
        // m[24] = (fr_add(m[49], m[44]));
        // (m[56], m[57]) = (ecc_mul(proof[48], proof[49], m[24]));
        update(m, proof, absorbing, uint256(105854138241167509566449766779827288738410722417553457939917398265320570642840));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[56], m[57]));
        // (m[56], m[57]) = (ecc_mul(proof[24], proof[25], m[55]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[56], m[57]));
        // m[0] = (fr_add(m[0], m[53]));
        // (m[56], m[57]) = (ecc_mul(proof[50], proof[51], m[0]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[56], m[57]));
        // (m[56], m[57]) = (ecc_mul(proof[28], proof[29], m[28]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[56], m[57]));
        update(m, proof, absorbing, uint256(105854138525091402186250165666445137529560829492155418467602734213431418114488));
        // m[0] = (fr_add(m[11], m[8]));
        // (m[56], m[57]) = (ecc_mul(proof[52], proof[53], m[0]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[56], m[57]));
        // (m[56], m[57]) = (ecc_mul(proof[32], proof[33], m[12]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[56], m[57]));
        // m[0] = (fr_add(1, m[32]));
        // (m[56], m[57]) = (ecc_mul(proof[54], proof[55], m[0]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[56], m[57]));
        update(m, proof, absorbing, uint256(43434563825235176358090933258341358051310073892846886780690103789235626004920));
        // (m[2], m[3]) = (ecc_mul(proof[36], proof[37], m[3]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[2], m[3]));
        update(m, proof, absorbing, uint256(16180388392151241090));
        (m[2], m[3]) = (ecc_mul(9116415356345615555811159776381652193168193787828239179565802674762682569973, 4428184940191662498286989946775629850985532133007156340972092328044210908854, m[19]));
        // (m[2], m[3]) = (ecc_add(m[40], m[41], m[2], m[3]));
        update(m, proof, absorbing, uint256(3766964610));
        (m[40], m[41]) = (ecc_mul(5782803705244881061263361621569960311277274931602059364909209792416853462843, 15062957458787329264595214692406450765681943945146362131527482334922095709034, m[37]));
        // (m[40], m[41]) = (ecc_add(m[2], m[3], m[40], m[41]));
        update(m, proof, absorbing, uint256(3926328744));
        (m[2], m[3]) = (ecc_mul(14644358055486067079343698621272998942731675195777908307503676891259978026953, 16295736872894509938791771324839081659430186572610185537283579311971011421292, m[45]));
        // (m[2], m[3]) = (ecc_add(m[40], m[41], m[2], m[3]));
        update(m, proof, absorbing, uint256(3766964610));
        (m[40], m[41]) = (ecc_mul(17116707133955884836357006178207620761007611328212792030784757608854661284485, 10564235754640126479094452759034342838818178798537892468702285136620994678178, m[38]));
        // (m[2], m[3]) = (ecc_add(m[2], m[3], m[40], m[41]));
        update(m, proof, absorbing, uint256(3766945192));
        (m[40], m[41]) = (ecc_mul(6135951017181396300356800259378210148999114301549298675044339423857898980919, 5815487117276505141264581921148900472128751426892854296990926822300013712644, m[33]));
        // (m[40], m[41]) = (ecc_add(m[2], m[3], m[40], m[41]));
        update(m, proof, absorbing, uint256(3926328744));
        (m[2], m[3]) = (ecc_mul(8157689213152512992213821877426256109974319146546820557446752076098013207101, 20331788656236305071458773610223833729452353814927042863466050043371792298564, m[25]));
        // (m[2], m[3]) = (ecc_add(m[40], m[41], m[2], m[3]));
        update(m, proof, absorbing, uint256(3766964610));
        (m[40], m[41]) = (ecc_mul(15608416851084762450836314372956714983290876172102962515382328946272631816537, 19602818359472118841528702513697079158282291420260785035137417435111425576917, m[22]));
        // (m[40], m[41]) = (ecc_add(m[2], m[3], m[40], m[41]));
        update(m, proof, absorbing, uint256(3926328744));
        (m[2], m[3]) = (ecc_mul(7965659214525635785209434554887419746172145594268295326365524496637495005895, 21594193019653125825171264190170924381366327572705644736196461883000697666896, m[1]));
        // (m[40], m[41]) = (ecc_add(m[40], m[41], m[2], m[3]));
        update(m, proof, absorbing, uint256(3926348162));
        (m[2], m[3]) = (ecc_mul(13914364856267104160118636963701154902761665282219140771590059906622916170099, 13262968012464745387745564604198002166707133433521463321591789339602700686829, m[17]));
        // (m[2], m[3]) = (ecc_add(m[40], m[41], m[2], m[3]));
        update(m, proof, absorbing, uint256(3766964610));
        (m[30], m[31]) = (ecc_mul(2918703644893990368797819857520248778893996242905236010699941158026844665879, 19496267097167811507037659097715355673325660448809069096731698348531894341840, m[31]));
        // (m[30], m[31]) = (ecc_add(m[2], m[3], m[30], m[31]));
        update(m, proof, absorbing, uint256(3884385694));
        (m[2], m[3]) = (ecc_mul(21537162186981550637121053147454964150809482185492418377558290311964245821909, 2173324946696678910860567153502925685634606622474439126082176533839311460335, m[36]));
        // (m[30], m[31]) = (ecc_add(m[30], m[31], m[2], m[3]));
        update(m, proof, absorbing, uint256(3884400002));
        (m[2], m[3]) = (ecc_mul(2655782365581423005140311563928797173442552504268175733975561296199753645700, 6201813071213189922368842916956898830484939074076765869016377279154166488665, m[18]));
        // (m[30], m[31]) = (ecc_add(m[30], m[31], m[2], m[3]));
        update(m, proof, absorbing, uint256(3884400002));
        (m[2], m[3]) = (ecc_mul(5422170891120229182360564594866246906567981360038071999127508208070564034524, 14722029885921976755274052080011416898514630484317773275415621146460924728182, m[54]));
        // (m[30], m[31]) = (ecc_add(m[30], m[31], m[2], m[3]));
        update(m, proof, absorbing, uint256(3884400002));
        (m[2], m[3]) = (ecc_mul(17737084440110923269096622656724713246088755105538145774000407295005556908838, 4203685513523885893207946609241749074248503765947670924993640699929083906981, m[20]));
        // (m[30], m[31]) = (ecc_add(m[30], m[31], m[2], m[3]));
        update(m, proof, absorbing, uint256(3884400002));
        (m[2], m[3]) = (ecc_mul(18451207565454686459225553564649439057698581050443267052774483067774590965003, 4419693978684087696088612463773850574955779922948673330581664932100506990694, m[48]));
        // (m[30], m[31]) = (ecc_add(m[30], m[31], m[2], m[3]));
        update(m, proof, absorbing, uint256(3884400002));
        (m[2], m[3]) = (ecc_mul(16437555853198616706213245075298393724621201055553861909595452106780033643573, 13086685446445802871119268707398694965556002011098720179711647124889361919943, m[29]));
        // (m[30], m[31]) = (ecc_add(m[30], m[31], m[2], m[3]));
        update(m, proof, absorbing, uint256(3884400002));
        (m[2], m[3]) = (ecc_mul(5422170891120229182360564594866246906567981360038071999127508208070564034524, 14722029885921976755274052080011416898514630484317773275415621146460924728182, m[71]));
        // (m[30], m[31]) = (ecc_add(m[30], m[31], m[2], m[3]));
        update(m, proof, absorbing, uint256(3884400002));
        (m[2], m[3]) = (ecc_mul(467984811404381813300121748905246620469194962855793933017395123543651662002, 9396518858838387398787470634456455001861925061455327319027891612754570465671, m[64]));
        // (m[2], m[3]) = (ecc_add(m[30], m[31], m[2], m[3]));
        update(m, proof, absorbing, uint256(3766959490));
        (m[70], m[71]) = (ecc_mul(1073209211341742528311189867664560455130715901362709093276808245867660371678, 19736041634240789293257190949105212732052786544170823808932102725097413859664, m[6]));
        // (m[2], m[3]) = (ecc_add(m[2], m[3], m[70], m[71]));
        update(m, proof, absorbing, uint256(3766945222));
        (m[70], m[71]) = (ecc_mul(11566905302404529781402371322023566311209586760145906818001162790190141985866, 13255797634361619644806915185016016139127910818219580229648105088798927340127, m[50]));
        // (m[2], m[3]) = (ecc_add(m[2], m[3], m[70], m[71]));
        update(m, proof, absorbing, uint256(3766945222));
        (m[70], m[71]) = (ecc_mul(19687193283782764679821278083169965097872078443982760551370812189881622756617, 21612445309108692993949827009335467001279824325715773969346324126663073649477, m[34]));
        // (m[2], m[3]) = (ecc_add(m[2], m[3], m[70], m[71]));
        update(m, proof, absorbing, uint256(3766945222));
        (m[70], m[71]) = (ecc_mul(8612688236720592481328836119381213598229728652791823664483828654980135610419, 13007728640223969706615008551466781366935860418326597597940783270192497225377, m[42]));
        // (m[2], m[3]) = (ecc_add(m[2], m[3], m[70], m[71]));
        update(m, proof, absorbing, uint256(3766945222));
        (m[70], m[71]) = (ecc_mul(18311107688247166194645894987623242775398986720572758069846491409878328409197, 9906741143387019721693223714748064890337165426210513616589722143371256265292, m[51]));
        // (m[2], m[3]) = (ecc_add(m[2], m[3], m[70], m[71]));
        // (m[70], m[71]) = (ecc_mul(proof[64], proof[65], m[61]));
        // (m[2], m[3]) = (ecc_add(m[2], m[3], m[70], m[71]));
        // (m[70], m[71]) = (ecc_mul(proof[62], proof[63], m[73]));
        // (m[2], m[3]) = (ecc_add(m[2], m[3], m[70], m[71]));
        // (m[70], m[71]) = (ecc_mul(proof[60], proof[61], m[9]));
        // (m[2], m[3]) = (ecc_add(m[2], m[3], m[70], m[71]));
        // (m[70], m[71]) = (ecc_mul(proof[58], proof[59], m[43]));
        update(m, proof, absorbing, uint256(101556642308635990367277831777620211275990789382385589889199096019164576118187));
        // (m[2], m[3]) = (ecc_add(m[2], m[3], m[70], m[71]));
        // (m[70], m[71]) = (ecc_mul(proof[56], proof[57], m[10]));
        // (m[2], m[3]) = (ecc_add(m[2], m[3], m[70], m[71]));
        // (m[70], m[71]) = (ecc_mul(proof[143], proof[144], m[4]));
        // (m[2], m[3]) = (ecc_add(m[2], m[3], m[70], m[71]));
        update(m, proof, absorbing, uint256(1281825036524753168158999664773595834183852688838));
        (m[70], m[71]) = (ecc_mul(1, 2, m[35]));
        // (m[2], m[3]) = (ecc_sub(m[2], m[3], m[70], m[71]));
        update(m, proof, absorbing, uint256(3767207366));
        return [ecc_from(m[26], m[27]), ecc_from(m[2], m[3])];
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
