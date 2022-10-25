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

    function fr_mul_add(
        uint256 a,
        uint256 b,
        uint256 c
    ) internal pure returns (uint256) {
        return addmod(mulmod(a, b, q_mod), c, q_mod);
    }

    function fr_mul_add_pm(
        uint256[64] memory m,
        uint256[] calldata proof,
        uint256 opcode,
        uint256 t
    ) internal pure returns (uint256) {
        for (uint256 i = 0; i < 32; i += 2) {
            uint256 a = opcode & 0xff;
            if (a != 0xff) {
                opcode >>= 8;
                uint256 b = opcode & 0xff;
                opcode >>= 8;
                t = addmod(mulmod(proof[a], m[b], q_mod), t, q_mod);
            } else {
                break;
            }
        }

        return t;
    }

    function fr_mul_add_mt(
        uint256[64] memory m,
        uint256 base,
        uint256 opcode,
        uint256 t
    ) internal pure returns (uint256) {
        for (uint256 i = 0; i < 32; i += 1) {
            uint256 a = opcode & 0xff;
            if (a != 0xff) {
                opcode >>= 8;
                t = addmod(mulmod(base, t, q_mod), m[a], q_mod);
            } else {
                break;
            }
        }

        return t;
    }

    function fr_reverse(uint256 input) internal pure returns (uint256 v) {
        v = input;

        // swap bytes
        v =
            ((v &
                0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >>
                8) |
            ((v &
                0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) <<
                8);

        // swap 2-byte long pairs
        v =
            ((v &
                0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >>
                16) |
            ((v &
                0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) <<
                16);

        // swap 4-byte long pairs
        v =
            ((v &
                0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >>
                32) |
            ((v &
                0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) <<
                32);

        // swap 8-byte long pairs
        v =
            ((v &
                0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >>
                64) |
            ((v &
                0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) <<
                64);

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

    function ecc_add(
        uint256 ax,
        uint256 ay,
        uint256 bx,
        uint256 by
    ) internal view returns (uint256, uint256) {
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

    function ecc_sub(
        uint256 ax,
        uint256 ay,
        uint256 bx,
        uint256 by
    ) internal view returns (uint256, uint256) {
        return ecc_add(ax, ay, bx, p_mod - by);
    }

    function ecc_mul(
        uint256 px,
        uint256 py,
        uint256 s
    ) internal view returns (uint256, uint256) {
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

    function _ecc_mul_add(uint256[5] memory input) internal view {
        bool ret = false;

        assembly {
            ret := staticcall(gas(), 7, input, 0x60, add(input, 0x20), 0x40)
        }
        require(ret);

        assembly {
            ret := staticcall(
                gas(),
                6,
                add(input, 0x20),
                0x80,
                add(input, 0x60),
                0x40
            )
        }
        require(ret);
    }

    function ecc_mul_add(
        uint256 px,
        uint256 py,
        uint256 s,
        uint256 qx,
        uint256 qy
    ) internal view returns (uint256, uint256) {
        uint256[5] memory input;
        input[0] = px;
        input[1] = py;
        input[2] = s;
        input[3] = qx;
        input[4] = qy;

        _ecc_mul_add(input);

        return (input[3], input[4]);
    }

    function ecc_mul_add_pm(
        uint256[64] memory m,
        uint256[] calldata proof,
        uint256 opcode,
        uint256 t0,
        uint256 t1
    ) internal view returns (uint256, uint256) {
        uint256[5] memory input;
        input[3] = t0;
        input[4] = t1;
        for (uint256 i = 0; i < 32; i += 2) {
            uint256 a = opcode & 0xff;
            if (a != 0xff) {
                opcode >>= 8;
                uint256 b = opcode & 0xff;
                opcode >>= 8;
                input[0] = proof[a];
                input[1] = proof[a + 1];
                input[2] = m[b];
                _ecc_mul_add(input);
            } else {
                break;
            }
        }

        return (input[3], input[4]);
    }

    function update_hash_scalar(
        uint256 v,
        uint256[128] memory absorbing,
        uint256 pos
    ) internal pure {
        absorbing[pos++] = 0x02;
        absorbing[pos++] = v;
    }

    function update_hash_point(
        uint256 x,
        uint256 y,
        uint256[128] memory absorbing,
        uint256 pos
    ) internal pure {
        absorbing[pos++] = 0x01;
        absorbing[pos++] = x;
        absorbing[pos++] = y;
    }

    function to_scalar(bytes32 r) private pure returns (uint256 v) {
        uint256 tmp = uint256(r);
        tmp = fr_reverse(tmp);
        v =
            tmp %
            0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    }

    function hash(uint256[128] memory absorbing, uint256 length)
        private
        view
        returns (bytes32[1] memory v)
    {
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 2, absorbing, length, v, 32)
            switch success
            case 0 {
                invalid()
            }
        }
        assert(success);
    }

    function squeeze_challenge(uint256[128] memory absorbing, uint32 length)
        internal
        view
        returns (uint256 v)
    {
        absorbing[length] = 0;
        bytes32 res = hash(absorbing, length * 32 + 1)[0];
        v = to_scalar(res);
        absorbing[0] = uint256(res);
        length = 1;
    }

    function get_verify_circuit_g2_s()
        internal
        pure
        returns (G2Point memory s)
    {
        s.x[0] = uint256(
            10425127071646585393062033862729405632829049123578498276429950016663998328285
        );
        s.x[1] = uint256(
            13096820816185996475938340599086778820334881006075204567436438707076195898474
        );
        s.y[0] = uint256(
            12404600459702921618619330621191150771271443490631506336545438712004980300417
        );
        s.y[1] = uint256(
            10397760085061689705691766595956174114157488599486621144912449227594279051498
        );
    }

    function get_verify_circuit_g2_n()
        internal
        pure
        returns (G2Point memory n)
    {
        n.x[0] = uint256(
            11559732032986387107991004021392285783925812861821192530917403151452391805634
        );
        n.x[1] = uint256(
            10857046999023057135944570762232829481370756359578518086990519993285655852781
        );
        n.y[0] = uint256(
            17805874995975841540914202342111839520379459829704422454583296818431106115052
        );
        n.y[1] = uint256(
            13392588948715843804641432497768002650278120570034223513918757245338268106653
        );
    }

    function get_target_circuit_g2_s()
        internal
        pure
        returns (G2Point memory s)
    {
        s.x[0] = uint256(
            7098581429220210747060744852057722197150633212484572619185538655856707476131
        );
        s.x[1] = uint256(
            11693647023436587219744022135226641138601479386305295859303161657067829498789
        );
        s.y[0] = uint256(
            3137595343812956275111043816665832676032201031765225035108594791591387293768
        );
        s.y[1] = uint256(
            9821685374621660143296871468720026156657530702543786106965987942160068228367
        );
    }

    function get_target_circuit_g2_n()
        internal
        pure
        returns (G2Point memory n)
    {
        n.x[0] = uint256(
            11559732032986387107991004021392285783925812861821192530917403151452391805634
        );
        n.x[1] = uint256(
            10857046999023057135944570762232829481370756359578518086990519993285655852781
        );
        n.y[0] = uint256(
            17805874995975841540914202342111839520379459829704422454583296818431106115052
        );
        n.y[1] = uint256(
            13392588948715843804641432497768002650278120570034223513918757245338268106653
        );
    }

    function get_wx_wg(uint256[] calldata proof, uint256[5] memory instances)
        internal
        view
        returns (
            uint256,
            uint256,
            uint256,
            uint256
        )
    {
        uint256[64] memory m;
        uint256[128] memory absorbing;
        uint256 t0 = 0;
        uint256 t1 = 0;

        (t0, t1) = (
            ecc_mul(
                12734578092696668220756864874597675975529895061728282136096629245128858885921,
                9902475631314106103558193612462511921326827461622017342311587399979109876190,
                instances[0]
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                18944201249822062511567071830917779901251617760767116645919431029135191318392,
                15877740901183820918511347088555245663498191329560214044094621189624340808361,
                instances[1],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                15201408788172462919638478643708537026489673076900456309920356124889802521950,
                12767972580993710048699464800479790602695401941396435684091297233233550152331,
                instances[2],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                18424929421796536752394468241338266279181641892537185800130599852076598074467,
                3578213005659776623388581219025180764543475092919276165899128486292147330742,
                instances[3],
                t0,
                t1
            )
        );
        (m[0], m[1]) = (
            ecc_mul_add(
                12600135169573070882676977319476100574864099423037330369878280499918687760750,
                19111530037494614858476178826888481330711932111832670608865472038668932124615,
                instances[4],
                t0,
                t1
            )
        );
        update_hash_scalar(
            13951719720029520059396067922068991321866177702353129131073363877433718599853,
            absorbing,
            0
        );
        update_hash_point(m[0], m[1], absorbing, 2);
        for (t0 = 0; t0 <= 6; t0++) {
            update_hash_point(
                proof[0 + t0 * 2],
                proof[1 + t0 * 2],
                absorbing,
                5 + t0 * 3
            );
        }
        m[2] = (squeeze_challenge(absorbing, 26));
        for (t0 = 0; t0 <= 1; t0++) {
            update_hash_point(
                proof[14 + t0 * 2],
                proof[15 + t0 * 2],
                absorbing,
                1 + t0 * 3
            );
        }
        m[3] = (squeeze_challenge(absorbing, 7));
        m[4] = (squeeze_challenge(absorbing, 1));
        for (t0 = 0; t0 <= 6; t0++) {
            update_hash_point(
                proof[18 + t0 * 2],
                proof[19 + t0 * 2],
                absorbing,
                1 + t0 * 3
            );
        }
        m[5] = (squeeze_challenge(absorbing, 22));
        for (t0 = 0; t0 <= 2; t0++) {
            update_hash_point(
                proof[32 + t0 * 2],
                proof[33 + t0 * 2],
                absorbing,
                1 + t0 * 3
            );
        }
        m[6] = (squeeze_challenge(absorbing, 10));
        for (t0 = 0; t0 <= 62; t0++) {
            update_hash_scalar(proof[38 + t0 * 1], absorbing, 1 + t0 * 2);
        }
        m[7] = (squeeze_challenge(absorbing, 127));
        m[8] = (squeeze_challenge(absorbing, 1));
        for (t0 = 0; t0 <= 5; t0++) {
            update_hash_point(
                proof[101 + t0 * 2],
                proof[102 + t0 * 2],
                absorbing,
                1 + t0 * 3
            );
        }
        m[9] = (
            mulmod(
                m[6],
                1426404432721484388505361748317961535523355871255605456897797744433766488507,
                q_mod
            )
        );
        m[10] = (
            mulmod(
                m[6],
                20975929243409798062839949658616274858986091382510192949221301676705706354487,
                q_mod
            )
        );
        m[11] = (
            mulmod(
                m[6],
                2785514556381676080176937710880804108647911392478702105860685610379369825016,
                q_mod
            )
        );
        m[12] = (fr_pow(m[6], 2097152));
        m[13] = (addmod(m[12], q_mod - 1, q_mod));
        m[14] = (
            mulmod(
                21888232434711746154598842647110004286396165347431605739555851272621938401409,
                m[13],
                q_mod
            )
        );
        t0 = (addmod(m[6], q_mod - 1, q_mod));
        m[14] = (fr_div(m[14], t0));
        m[15] = (
            mulmod(
                4951124136965839578869076322913110736946738986360144227279799065540645651954,
                m[13],
                q_mod
            )
        );
        t0 = (
            addmod(
                m[6],
                q_mod -
                    2785514556381676080176937710880804108647911392478702105860685610379369825016,
                q_mod
            )
        );
        m[15] = (fr_div(m[15], t0));
        m[16] = (
            mulmod(
                19030992621249220901783546889149655643269617254601816267839801549493209742555,
                m[13],
                q_mod
            )
        );
        t0 = (
            addmod(
                m[6],
                q_mod -
                    15402826414547299628414612080036060696555554914079673875872749760617770134879,
                q_mod
            )
        );
        m[16] = (fr_div(m[16], t0));
        m[17] = (
            mulmod(
                18157841278220448929024800528040825917376485016118551429083090763641518722097,
                m[13],
                q_mod
            )
        );
        t0 = (
            addmod(
                m[6],
                q_mod -
                    10939663269433627367777756708678102241564365262857670666700619874077960926249,
                q_mod
            )
        );
        m[17] = (fr_div(m[17], t0));
        m[18] = (
            mulmod(
                20390219397793851549016004518348241218777667304519355398360945264991944816248,
                m[13],
                q_mod
            )
        );
        t0 = (
            addmod(
                m[6],
                q_mod -
                    14686510910986211321976396297238126901237973400949744736326777596334651355305,
                q_mod
            )
        );
        m[18] = (fr_div(m[18], t0));
        m[19] = (
            mulmod(
                5446466104292484738405343879038119272479454743548880569397846660937080193551,
                m[13],
                q_mod
            )
        );
        t0 = (
            addmod(
                m[6],
                q_mod -
                    16064522944768515290584536219762686197737451920702130080538975732575755569557,
                q_mod
            )
        );
        m[19] = (fr_div(m[19], t0));
        m[20] = (
            mulmod(
                15333340845990456061001622359348979431577398234184450975706184089850976679978,
                m[13],
                q_mod
            )
        );
        t0 = (
            addmod(
                m[6],
                q_mod -
                    495188420091111145957709789221178673495499187437761988132837836548330853701,
                q_mod
            )
        );
        m[20] = (fr_div(m[20], t0));
        m[21] = (
            mulmod(
                6051299986542977139724824521524261404747425289147659770085340755279317776841,
                m[13],
                q_mod
            )
        );
        t0 = (
            addmod(
                m[6],
                q_mod -
                    20975929243409798062839949658616274858986091382510192949221301676705706354487,
                q_mod
            )
        );
        m[21] = (fr_div(m[21], t0));
        t0 = (addmod(m[15], m[16], q_mod));
        t0 = (addmod(t0, m[17], q_mod));
        t0 = (addmod(t0, m[18], q_mod));
        t0 = (addmod(t0, m[19], q_mod));
        m[15] = (addmod(t0, m[20], q_mod));
        m[16] = (fr_mul_add(proof[41], proof[40], proof[39]));
        t0 = (addmod(0, q_mod - proof[42], q_mod));
        t0 = (addmod(m[16], t0, q_mod));
        m[16] = (mulmod(proof[65], t0, q_mod));
        m[17] = (fr_mul_add(proof[45], proof[44], proof[43]));
        t0 = (addmod(0, q_mod - proof[46], q_mod));
        t0 = (addmod(m[17], t0, q_mod));
        m[17] = (mulmod(proof[66], t0, q_mod));
        m[18] = (fr_mul_add(proof[49], proof[48], proof[47]));
        t0 = (addmod(0, q_mod - proof[50], q_mod));
        t0 = (addmod(m[18], t0, q_mod));
        m[18] = (mulmod(proof[67], t0, q_mod));
        m[19] = (fr_mul_add(proof[53], proof[52], proof[51]));
        t0 = (addmod(0, q_mod - proof[54], q_mod));
        t0 = (addmod(m[19], t0, q_mod));
        m[19] = (mulmod(proof[68], t0, q_mod));
        m[20] = (fr_mul_add(proof[57], proof[56], proof[55]));
        t0 = (addmod(0, q_mod - proof[58], q_mod));
        t0 = (addmod(m[20], t0, q_mod));
        m[20] = (mulmod(proof[69], t0, q_mod));
        m[22] = (fr_mul_add(proof[61], proof[60], proof[59]));
        t0 = (addmod(0, q_mod - proof[62], q_mod));
        t0 = (addmod(m[22], t0, q_mod));
        m[22] = (mulmod(proof[70], t0, q_mod));
        t0 = (addmod(1, q_mod - proof[82], q_mod));
        m[23] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[94], proof[94], q_mod));
        t0 = (addmod(t0, q_mod - proof[94], q_mod));
        m[24] = (mulmod(m[21], t0, q_mod));
        t0 = (addmod(proof[85], q_mod - proof[84], q_mod));
        m[25] = (mulmod(t0, m[14], q_mod));
        t0 = (addmod(proof[88], q_mod - proof[87], q_mod));
        m[26] = (mulmod(t0, m[14], q_mod));
        t0 = (addmod(proof[91], q_mod - proof[90], q_mod));
        m[27] = (mulmod(t0, m[14], q_mod));
        t0 = (addmod(proof[94], q_mod - proof[93], q_mod));
        m[28] = (mulmod(t0, m[14], q_mod));
        m[29] = (mulmod(m[3], m[6], q_mod));
        t0 = (addmod(m[21], m[15], q_mod));
        m[15] = (addmod(1, q_mod - t0, q_mod));
        m[30] = (addmod(proof[64], m[4], q_mod));
        t0 = (fr_mul_add(proof[73], m[3], m[30]));
        m[31] = (mulmod(t0, proof[83], q_mod));
        t0 = (addmod(m[30], m[29], q_mod));
        m[30] = (mulmod(t0, proof[82], q_mod));
        m[32] = (
            mulmod(
                4131629893567559867359510883348571134090853742863529169391034518566172092834,
                m[29],
                q_mod
            )
        );
        m[33] = (addmod(proof[39], m[4], q_mod));
        t0 = (fr_mul_add(proof[74], m[3], m[33]));
        m[31] = (mulmod(t0, m[31], q_mod));
        t0 = (addmod(m[33], m[32], q_mod));
        m[30] = (mulmod(t0, m[30], q_mod));
        m[32] = (
            mulmod(
                4131629893567559867359510883348571134090853742863529169391034518566172092834,
                m[32],
                q_mod
            )
        );
        t0 = (addmod(m[31], q_mod - m[30], q_mod));
        m[30] = (mulmod(t0, m[15], q_mod));
        m[31] = (
            mulmod(
                m[29],
                8910878055287538404433155982483128285667088683464058436815641868457422632747,
                q_mod
            )
        );
        m[32] = (addmod(proof[43], m[4], q_mod));
        t0 = (fr_mul_add(proof[75], m[3], m[32]));
        m[33] = (mulmod(t0, proof[86], q_mod));
        t0 = (addmod(m[32], m[31], q_mod));
        m[32] = (mulmod(t0, proof[85], q_mod));
        m[31] = (
            mulmod(
                4131629893567559867359510883348571134090853742863529169391034518566172092834,
                m[31],
                q_mod
            )
        );
        m[34] = (addmod(proof[47], m[4], q_mod));
        t0 = (fr_mul_add(proof[76], m[3], m[34]));
        m[33] = (mulmod(t0, m[33], q_mod));
        t0 = (addmod(m[34], m[31], q_mod));
        m[32] = (mulmod(t0, m[32], q_mod));
        m[31] = (
            mulmod(
                4131629893567559867359510883348571134090853742863529169391034518566172092834,
                m[31],
                q_mod
            )
        );
        t0 = (addmod(m[33], q_mod - m[32], q_mod));
        m[31] = (mulmod(t0, m[15], q_mod));
        m[32] = (
            mulmod(
                m[29],
                284840088355319032285349970403338060113257071685626700086398481893096618818,
                q_mod
            )
        );
        m[33] = (addmod(proof[51], m[4], q_mod));
        t0 = (fr_mul_add(proof[77], m[3], m[33]));
        m[34] = (mulmod(t0, proof[89], q_mod));
        t0 = (addmod(m[33], m[32], q_mod));
        m[33] = (mulmod(t0, proof[88], q_mod));
        m[32] = (
            mulmod(
                4131629893567559867359510883348571134090853742863529169391034518566172092834,
                m[32],
                q_mod
            )
        );
        m[35] = (addmod(proof[55], m[4], q_mod));
        t0 = (fr_mul_add(proof[78], m[3], m[35]));
        m[34] = (mulmod(t0, m[34], q_mod));
        t0 = (addmod(m[35], m[32], q_mod));
        m[33] = (mulmod(t0, m[33], q_mod));
        m[32] = (
            mulmod(
                4131629893567559867359510883348571134090853742863529169391034518566172092834,
                m[32],
                q_mod
            )
        );
        t0 = (addmod(m[34], q_mod - m[33], q_mod));
        m[32] = (mulmod(t0, m[15], q_mod));
        m[33] = (
            mulmod(
                m[29],
                5625741653535312224677218588085279924365897425605943700675464992185016992283,
                q_mod
            )
        );
        m[34] = (addmod(proof[59], m[4], q_mod));
        t0 = (fr_mul_add(proof[79], m[3], m[34]));
        m[35] = (mulmod(t0, proof[92], q_mod));
        t0 = (addmod(m[34], m[33], q_mod));
        m[34] = (mulmod(t0, proof[91], q_mod));
        m[33] = (
            mulmod(
                4131629893567559867359510883348571134090853742863529169391034518566172092834,
                m[33],
                q_mod
            )
        );
        m[36] = (addmod(proof[63], m[4], q_mod));
        t0 = (fr_mul_add(proof[80], m[3], m[36]));
        m[35] = (mulmod(t0, m[35], q_mod));
        t0 = (addmod(m[36], m[33], q_mod));
        m[34] = (mulmod(t0, m[34], q_mod));
        m[33] = (
            mulmod(
                4131629893567559867359510883348571134090853742863529169391034518566172092834,
                m[33],
                q_mod
            )
        );
        t0 = (addmod(m[35], q_mod - m[34], q_mod));
        m[33] = (mulmod(t0, m[15], q_mod));
        m[29] = (
            mulmod(
                m[29],
                8343274462013750416000956870576256937330525306073862550863787263304548803879,
                q_mod
            )
        );
        m[34] = (addmod(proof[38], m[4], q_mod));
        t0 = (fr_mul_add(proof[81], m[3], m[34]));
        m[35] = (mulmod(t0, proof[95], q_mod));
        t0 = (addmod(m[34], m[29], q_mod));
        m[34] = (mulmod(t0, proof[94], q_mod));
        m[29] = (
            mulmod(
                4131629893567559867359510883348571134090853742863529169391034518566172092834,
                m[29],
                q_mod
            )
        );
        t0 = (addmod(m[35], q_mod - m[34], q_mod));
        m[29] = (mulmod(t0, m[15], q_mod));
        t0 = (addmod(proof[98], m[3], q_mod));
        m[34] = (mulmod(proof[97], t0, q_mod));
        t0 = (addmod(proof[100], m[4], q_mod));
        m[34] = (mulmod(m[34], t0, q_mod));
        m[2] = (mulmod(0, m[2], q_mod));
        m[35] = (addmod(m[2], proof[63], q_mod));
        m[2] = (addmod(m[2], proof[71], q_mod));
        m[36] = (addmod(proof[98], q_mod - proof[100], q_mod));
        t0 = (addmod(1, q_mod - proof[96], q_mod));
        m[37] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[96], proof[96], q_mod));
        t0 = (addmod(t0, q_mod - proof[96], q_mod));
        m[21] = (mulmod(m[21], t0, q_mod));
        t0 = (addmod(m[35], m[3], q_mod));
        m[3] = (mulmod(proof[96], t0, q_mod));
        t0 = (addmod(m[2], m[4], q_mod));
        t0 = (mulmod(m[3], t0, q_mod));
        t0 = (addmod(m[34], q_mod - t0, q_mod));
        m[2] = (mulmod(t0, m[15], q_mod));
        m[3] = (mulmod(m[14], m[36], q_mod));
        t0 = (addmod(proof[98], q_mod - proof[99], q_mod));
        t0 = (mulmod(m[36], t0, q_mod));
        m[4] = (mulmod(t0, m[15], q_mod));
        m[14] = (
            mulmod(
                m[6],
                19032961837237948602743626455740240236231119053033140765040043513661803148152,
                q_mod
            )
        );
        m[15] = (
            mulmod(
                m[6],
                3766081621734395783232337525162072736827576297943013392955872170138036189193,
                q_mod
            )
        );
        t0 = (fr_mul_add(m[5], 0, m[16]));
        t0 = (
            fr_mul_add_mt(
                m,
                m[5],
                95412690064926456152341396097372761852592969454129681,
                t0
            )
        );
        m[2] = (fr_div(t0, m[13]));
        m[3] = (mulmod(m[8], m[8], q_mod));
        m[4] = (mulmod(m[3], m[8], q_mod));
        m[5] = (mulmod(m[4], m[8], q_mod));
        m[13] = (mulmod(m[5], m[8], q_mod));
        (t0, t1) = (ecc_mul(proof[101], proof[102], m[13]));
        (t0, t1) = (
            ecc_mul_add_pm(m, proof, 1208907980015838400415079, t0, t1)
        );
        (m[16], m[17]) = (ecc_add(t0, t1, proof[111], proof[112]));
        m[10] = (mulmod(m[13], m[10], q_mod));
        m[18] = (mulmod(m[13], m[7], q_mod));
        m[19] = (mulmod(m[18], m[7], q_mod));
        m[20] = (mulmod(m[19], m[7], q_mod));
        t0 = (mulmod(m[20], proof[93], q_mod));
        t0 = (fr_mul_add_pm(m, proof, 281470989439834, t0));
        m[21] = (fr_mul_add(proof[84], m[13], t0));
        m[11] = (mulmod(m[5], m[11], q_mod));
        m[21] = (fr_mul_add(proof[99], m[5], m[21]));
        m[6] = (mulmod(m[4], m[6], q_mod));
        m[22] = (mulmod(m[4], m[7], q_mod));
        for (t0 = 0; t0 < 33; t0++) {
            m[23 + t0 * 1] = (mulmod(m[22 + t0 * 1], m[7 + t0 * 0], q_mod));
        }
        t0 = (mulmod(m[55], proof[38], q_mod));
        t0 = (
            fr_mul_add_pm(
                m,
                proof,
                17753558077099930996396666760789488611075161604781426658992052905242474001959,
                t0
            )
        );
        t0 = (
            fr_mul_add_pm(
                m,
                proof,
                115790490191624821662217017095107419377425949196599861519811516400776551474753,
                t0
            )
        );
        m[56] = (fr_mul_add(proof[81], m[23], t0));
        m[57] = (mulmod(m[22], m[12], q_mod));
        m[12] = (mulmod(m[57], m[12], q_mod));
        t0 = (fr_mul_add(m[22], m[2], m[56]));
        t0 = (fr_mul_add(proof[72], m[4], t0));
        m[2] = (addmod(m[21], t0, q_mod));
        m[13] = (addmod(m[13], m[47], q_mod));
        m[18] = (addmod(m[18], m[46], q_mod));
        m[19] = (addmod(m[19], m[45], q_mod));
        m[20] = (addmod(m[20], m[44], q_mod));
        m[5] = (addmod(m[5], m[41], q_mod));
        m[9] = (mulmod(m[3], m[9], q_mod));
        m[21] = (mulmod(m[3], m[7], q_mod));
        m[41] = (mulmod(m[21], m[7], q_mod));
        m[44] = (mulmod(m[41], m[7], q_mod));
        m[45] = (mulmod(m[44], m[7], q_mod));
        m[46] = (mulmod(m[45], m[7], q_mod));
        m[47] = (mulmod(m[46], m[7], q_mod));
        m[56] = (mulmod(m[47], m[7], q_mod));
        m[58] = (mulmod(m[56], m[7], q_mod));
        m[59] = (mulmod(m[58], m[7], q_mod));
        m[60] = (mulmod(m[59], m[7], q_mod));
        m[61] = (mulmod(m[60], m[7], q_mod));
        t0 = (mulmod(m[61], proof[40], q_mod));
        t0 = (
            fr_mul_add_pm(
                m,
                proof,
                95779631813460672555542360642039463194938936533204012,
                t0
            )
        );
        m[62] = (fr_mul_add(proof[97], m[3], t0));
        m[54] = (addmod(m[54], m[61], q_mod));
        m[2] = (addmod(m[2], m[62], q_mod));
        m[53] = (addmod(m[53], m[60], q_mod));
        m[52] = (addmod(m[52], m[59], q_mod));
        m[51] = (addmod(m[51], m[58], q_mod));
        m[50] = (addmod(m[50], m[56], q_mod));
        m[47] = (addmod(m[49], m[47], q_mod));
        m[13] = (addmod(m[13], m[46], q_mod));
        m[18] = (addmod(m[18], m[45], q_mod));
        m[19] = (addmod(m[19], m[44], q_mod));
        m[20] = (addmod(m[20], m[41], q_mod));
        m[21] = (addmod(m[43], m[21], q_mod));
        m[3] = (addmod(m[42], m[3], q_mod));
        m[14] = (mulmod(m[8], m[14], q_mod));
        m[41] = (mulmod(m[8], m[7], q_mod));
        m[42] = (mulmod(m[41], m[7], q_mod));
        m[43] = (mulmod(m[42], m[7], q_mod));
        m[44] = (mulmod(m[43], m[7], q_mod));
        m[45] = (mulmod(m[44], m[7], q_mod));
        t0 = (mulmod(m[45], proof[41], q_mod));
        t0 = (fr_mul_add_pm(m, proof, 1208910343322392538983469, t0));
        m[46] = (fr_mul_add(proof[61], m[8], t0));
        m[45] = (addmod(m[54], m[45], q_mod));
        m[2] = (addmod(m[2], m[46], q_mod));
        m[44] = (addmod(m[53], m[44], q_mod));
        m[43] = (addmod(m[52], m[43], q_mod));
        m[42] = (addmod(m[51], m[42], q_mod));
        m[41] = (addmod(m[50], m[41], q_mod));
        m[8] = (addmod(m[47], m[8], q_mod));
        m[46] = (mulmod(m[7], m[7], q_mod));
        m[47] = (mulmod(m[46], m[7], q_mod));
        m[49] = (mulmod(m[47], m[7], q_mod));
        m[50] = (mulmod(m[49], m[7], q_mod));
        t0 = (mulmod(m[50], proof[42], q_mod));
        t0 = (fr_mul_add_pm(m, proof, 1208907893650072634798382, t0));
        m[51] = (addmod(t0, proof[62], q_mod));
        m[45] = (addmod(m[45], m[50], q_mod));
        m[2] = (addmod(m[2], m[51], q_mod));
        m[44] = (addmod(m[44], m[49], q_mod));
        m[43] = (addmod(m[43], m[47], q_mod));
        m[42] = (addmod(m[42], m[46], q_mod));
        m[7] = (addmod(m[41], m[7], q_mod));
        m[8] = (addmod(m[8], 1, q_mod));
        (t0, t1) = (ecc_mul(proof[101], proof[102], m[10]));
        (t0, t1) = (
            ecc_mul_add_pm(
                m,
                proof,
                340277304639059018401093184400815166488,
                t0,
                t1
            )
        );
        (t0, t1) = (ecc_mul_add(m[0], m[1], m[55], t0, t1));
        (t0, t1) = (
            ecc_mul_add_pm(
                m,
                proof,
                95779738519194371688380630811371902770799208181148928,
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                5674756010620727403237304681921577550803882195616730202474630090208292576849,
                18447369268043620755468055464484180217676624607977706380919487950708919881324,
                m[31],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                1015916231845314323059904749310366356205294051772476131938544470201500758591,
                7511260629859134184018664193975756105095681929674620013641882434676346120147,
                m[30],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                4013469635698527918912205137881501983258607624422854135497547663226396052948,
                12857812639571629811960740677373872578716921045303231081216833399420529505766,
                m[29],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                18112936401783185006727527836256717627908002181095692766820514603733453766029,
                2501116022446108608311200929047309009729322908475281541694491850355164078071,
                m[28],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                13531583659943384465765894691766690389450525955891418414439075016040020551786,
                7440956556962827063049241604312040758090954042930154474185873043824325744159,
                m[27],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                1505984045149781863492420049590322410416201982683674253468277324824040625549,
                358900902170833235090934434089473871380201905092250855832840825773627473792,
                m[26],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                12474838076637315211066079478122166720729737483653663442639962626187790717092,
                20133373068553346360260621208823175070797260309624658791248211398322859139863,
                m[25],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                11623649543852492201508721179276193524776661875307778422074066836297678884076,
                2796642821135732597371565196071211982105796076508177810401483020636538042759,
                m[24],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                20038925330314151390285434546500326766228691547729542395504089678850825323187,
                7628331227209762125834000343176012595327166664434993689375591641843543261629,
                m[23],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add_pm(
                m,
                proof,
                340277487659014630021377395236611951652,
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                15530364427428977365494657490114035359184305339703963653941115489410079229695,
                17511812050020977968207391431136305889449511066909640060562578839884598562529,
                m[39],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                2777238675255493081616077661597490915591731167882897897828273663689008145174,
                398479550342199414553904096414896626597640347741391345990476121135047406924,
                m[38],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                2020669936623549972837768402035280176695177018999750264721932851644588930187,
                18025503403522146639575859561544972689922510057078866244709901761309908178508,
                m[37],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                13983808421038415131227266125109911898859875261169506740894079340447146640540,
                4777040341700973970588900731737905529908189675862661587218594605059192428030,
                m[36],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                4272328936883947527365941609308187889616347284763437503927240305547923800311,
                17580627494233540649826273835802106312288671113481885380567176514582904458771,
                m[35],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                3576946969330416885649173866801993947565350140359903639421377680174509495541,
                2904904346793129521232434026214583707431274755793911547731462225980551318097,
                m[34],
                t0,
                t1
            )
        );
        (t0, t1) = (
            ecc_mul_add(
                8934304486276543760969986118938926486170654163010864724615337751724708569831,
                15376636242917796956396509275685080007038807864093294335118509261698849913976,
                m[33],
                t0,
                t1
            )
        );
        (m[0], m[1]) = (
            ecc_mul_add(
                2590827918368538790049952780190258490603741079439167785003370356787481121082,
                19996351501794725282730447064529997499128186519535398269155178509274055170727,
                m[32],
                t0,
                t1
            )
        );
        (t0, t1) = (ecc_mul(1, 2, m[2]));
        (m[0], m[1]) = (ecc_sub(m[0], m[1], t0, t1));
        return (m[16], m[17], m[0], m[1]);
    }

    function verify(
        uint256[] calldata proof,
        uint256[] calldata target_circuit_final_pair
    ) external returns (bool checked) {
        uint256[5] memory instances;
        // 176 = 88 * 2, where 88 = limb bits
        instances[0] = target_circuit_final_pair[0] & ((1 << 176) - 1);
        instances[1] =
            (target_circuit_final_pair[0] >> 176) +
            ((target_circuit_final_pair[1] & 1) << 176);
        instances[2] = target_circuit_final_pair[2] & ((1 << 176) - 1);
        instances[3] =
            (target_circuit_final_pair[2] >> 176) +
            ((target_circuit_final_pair[3] & 1) << 176);

        instances[4] = target_circuit_final_pair[4];

        uint256 x0 = 0;
        uint256 x1 = 0;
        uint256 y0 = 0;
        uint256 y1 = 0;

        G1Point[] memory g1_points = new G1Point[](2);
        G2Point[] memory g2_points = new G2Point[](2);
        checked = false;

        (x0, y0, x1, y1) = get_wx_wg(proof, instances);
        g1_points[0].x = x0;
        g1_points[0].y = y0;
        g1_points[1].x = x1;
        g1_points[1].y = y1;
        g2_points[0] = get_verify_circuit_g2_s();
        g2_points[1] = get_verify_circuit_g2_n();

        checked = pairing(g1_points, g2_points);
        require(checked);

        g1_points[0].x = target_circuit_final_pair[0];
        g1_points[0].y = target_circuit_final_pair[1];
        g1_points[1].x = target_circuit_final_pair[2];
        g1_points[1].y = target_circuit_final_pair[3];
        g2_points[0] = get_target_circuit_g2_s();
        g2_points[1] = get_target_circuit_g2_n();

        checked = pairing(g1_points, g2_points);
        require(checked);

        return checked;
    }
}
