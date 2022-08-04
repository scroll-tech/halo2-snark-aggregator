import { expect, use } from "chai";
import { Contract } from "ethers";
import { deployContract, MockProvider, solidity } from "ethereum-waffle";
import Verifier from "../build/Verifier.json";
import fs from "fs";
import { BigNumber } from "@ethersproject/bignumber";

use(solidity);

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
  const provider = new MockProvider();
  const [wallet, walletTo] = provider.getWallets();
  let token: Contract;

  beforeEach(async () => {
    token = await deployContract(wallet, Verifier, [], { gasLimit: 6700000 });
/*
    token.on("Scalar", (x) => {
      console.log("Scalar", x.toString());
    })
*/
  });

  let proof = fs.readFileSync(
    "output/verify_circuit_proof.data"
  );
  let final_pair = fs.readFileSync(
    "output/verify_circuit_final_pair.data"
//	  "output/verify_circuit_instance.data"
  );
  console.log("proof length", proof.length);

  console.log(bufferToUint256LE(final_pair));

  it("Assigns initial balance", async () => {
    let a = await token.verify(
      bufferToUint256LE(proof),
      bufferToUint256LE(final_pair),
    );
    console.log(a.toString());
  });
});
