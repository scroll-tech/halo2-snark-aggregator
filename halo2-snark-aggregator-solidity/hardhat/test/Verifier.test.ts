import { expect } from "chai";
const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
import { ethers } from "hardhat";
import fs from "fs";
import { BigNumber } from "@ethersproject/bignumber";

function bufferToUint256BE(buffer: Buffer) {
  let buffer256 = [];
  for (let i = 0; i < buffer.length / 32; i++) {
    let v = BigNumber.from(0);
    for (let j = 0; j < 32; j++) {
      v = v.shl(8);
      v = v.add(buffer[i * 32 + j]);
    }
    buffer256.push(v);
  }

  return buffer256;
}

function bufferToUint256LE(buffer: Buffer) {
  let buffer256 = [];
  for (let i = 0; i < buffer.length / 32; i++) {
    let v = BigNumber.from(0);
    let shft = BigNumber.from(1);
    for (let j = 0; j < 32; j++) {
      v = v.add(shft.mul(buffer[i * 32 + j]));
      shft = shft.mul(256);
    }
    buffer256.push(v);
  }

  return buffer256;
}

describe("Verifier", () => {
  async function deployVerifierFixture() {
    const Verifier = await ethers.getContractFactory("Verifier");
    const hardhatVerifier = await Verifier.deploy({ gasLimit: 6700000 });

    await hardhatVerifier.deployed();

    // Fixtures can return anything you consider useful for your tests
    return { Verifier, hardhatVerifier };
  }

  it("Verify aggregation circuit proof", async () => {
    const { Verifier, hardhatVerifier } = await loadFixture(
      deployVerifierFixture
    );

    let proof = fs.readFileSync(
      "../../halo2-snark-aggregator-sdk/output/verify_circuit_proof.data"
    );
    let final_pair = fs.readFileSync(
      "../../halo2-snark-aggregator-sdk/output/verify_circuit_final_pair.data"
    );
    console.log("proof length", proof.length);

    console.log(bufferToUint256LE(final_pair));

    let a = await hardhatVerifier.verify(
      bufferToUint256LE(proof),
      bufferToUint256LE(final_pair)
    );
    console.log(a.gasPrice);
    // expect(a).to.equal(true);
  });
});
