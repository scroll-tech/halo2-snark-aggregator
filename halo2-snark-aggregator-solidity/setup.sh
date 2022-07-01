#!/bin/sh

mkdir -p waffle/
mkdir -p waffle/src
cp ../halo2-snark-aggregator-sdk/output/verifier.sol waffle/src/Verifier.sol
cd waffle
yarn install
yarn build
cd -
