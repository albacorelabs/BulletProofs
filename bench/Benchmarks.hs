module Main where

import Gauge.Main
import RangeProof

import Crypto.PubKey.ECC.Prim
import Crypto.PubKey.ECC.Generate

import Utils


main :: IO ()
main = do
    h <- generateQ crv <$> scalarGenerate crv
    rp <- generateQ crv <$> scalarGenerate crv
    let vBlinds = repeat 10
        vs = repeat 8
        ub = 8
        commV = (\(v,vBlind) -> pointAdd crv (pointMul crv vBlind h) (pointBaseMul crv (toInteger v))) <$> (take 1 $ zip vs vBlinds)
        commVs2 = (\(v,vBlind) -> pointAdd crv (pointMul crv vBlind h) (pointBaseMul crv (toInteger v))) <$> (take 2 $ zip vs vBlinds)
        commVs8 = (\(v,vBlind) -> pointAdd crv (pointMul crv vBlind h) (pointBaseMul crv (toInteger v))) <$> (take 8 $ zip vs vBlinds)
    range_proof <- generate_range_proof 8 (take 1 vs) (take 1 vBlinds) h rp
    range_proof2 <- generate_range_proof 8 (take 2 vs) (take 2 vBlinds) h rp
    range_proof8 <- generate_range_proof 8 (take 8 vs) (take 8 vBlinds) h rp
    -- let curriedVerify = (\x -> verify_range_proof x commVs h rp)
    -- verified <- verify_range_proof range_proof commV h rp
    
    defaultMain [
        bgroup "BulletProof Range Proof" [
            bench "Verifying 1 x 64-bit rangeproof" $ nf (\x -> verify_range_proof x commV h rp) range_proof,
            bench "Verifying 2 x 64-bit rangeproof" $ nf (\x -> verify_range_proof x commVs2 h rp) range_proof2,
            bench "Verifying 8 x 64-bit rangeproof" $ nf (\x -> verify_range_proof x commVs8 h rp) range_proof8
        ]
        ]