import {expect, use} from 'chai';
import {Contract} from 'ethers';
import {deployContract, MockProvider, solidity} from 'ethereum-waffle';
import Verifier from '../build/Verifier.json';
import fs from "fs";

use(solidity);

describe('Verifier', () => {
  const provider = new MockProvider();
  const [wallet, walletTo] = provider.getWallets();
  let token: Contract;

  beforeEach(async () => {
    token = await deployContract(wallet, Verifier, [], {gasLimit: 6700000});

    token.on("Scalar", (x) => {
      console.log("Scalar", x);
    })
  });

  let instances = fs.readFileSync("../../halo2-snark-aggregator/output/verify_circuit_instance_commitments.data");
  console.log(instances);
  let proof = fs.readFileSync("../../halo2-snark-aggregator/output/verify_circuit_proof_be.data");

  it('Assigns initial balance', async () => {
    expect(await token.verify(proof, instances));
  });
});
