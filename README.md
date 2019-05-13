# Bullet Proof 🔫  

Implementation of the Bulletproof Zk cryptosystem as described in [Bünz et al](https://eprint.iacr.org/2017/1066.pdf). Special thanks to [Adjoint IO](https://github.com/adjoint-io/bulletproofs) and [Adam Gibson](https://github.com/AdamISZ/from0k2bp) whose resources served as a helpful reference guide for this implementation.

## Brief Intro
Bulletproofs is a non-interactive zero-knowledge proof protocol with logarithmic sized proofs that do not require a trusted setup. Proof generation and verification scale linearly but optimisations can reduce these to sub-linear.


### *This library is currently experimental and still under development. Usage in production systems is not recommended*

## Development Milestones
[x] Range proof

[x] Range Proof aggregation

[ ] Optimised Single Multi-Exponentiation

[ ] Batch Verification

## Range Proof Overview
Bulletproof range proofs are logarithmic-sized. This is achieved through the transformation of the range proof constraints into a single inner product and application of the proof of inner product optimisation.


## Range Proof Usage
The two main functions are `generate_range_proof` and `verify_range_proof`. The former takes as inputs: a bitwise upperBound (n), an array of integer values values, their corresponding blinding factors and two randomly generated points used in the commitment and inner-product proof. The result is a proof that each value is between 0 and (2^n)-1.

`verify_range_proof` takes as inputs the range proof outputted from `generate_range_proof`, the array of commitments, and the two generated points.

```
import Crypto.PubKey.ECC.Prim
import Crypto.PubKey.ECC.Generate
import Crypto.PubKey.ECC.Types

run_rangeProof :: IO ()
run_rangeProof = do
    h <- generateQ crv <$> scalarGenerate crv
    rp <- generateQ crv <$> scalarGenerate crv
    let vBlinds = [10,12]
        vs = [8,9]
        commVs =  (\ (v,vBlind) -> pointAdd crv (pointMul crv vBlind h) (pointBaseMul crv (toInteger v))) <$> zip vs vBlinds
        uB = 8 -- # of Bits vs needs to below
    range_proof <- generate_range_proof uB vs vBlinds h rp
    let verified = verify_range_proof range_proof commVs h rp
```