module Main where

import Gauge.Main
import RangeProof

import Crypto.PubKey.ECC.Prim
import Crypto.PubKey.ECC.Generate

import Constants

main :: IO ()
main = do
    h <- generateQ crv <$> scalarGenerate crv
    let vBlinds = repeat 10
        vs = repeat 8
        ub = 64
        commV = (\(v,vBlind) -> pointAdd crv (pointMul crv vBlind h) (pointBaseMul crv (toInteger v))) <$> (take 1 $ zip vs vBlinds)
        commVs2 = (\(v,vBlind) -> pointAdd crv (pointMul crv vBlind h) (pointBaseMul crv (toInteger v))) <$> (take 2 $ zip vs vBlinds)
        commVs8 = (\(v,vBlind) -> pointAdd crv (pointMul crv vBlind h) (pointBaseMul crv (toInteger v))) <$> (take 8 $ zip vs vBlinds)
        commVs16 = (\(v,vBlind) -> pointAdd crv (pointMul crv vBlind h) (pointBaseMul crv (toInteger v))) <$> (take 16 $ zip vs vBlinds)
        commVs32 = (\(v,vBlind) -> pointAdd crv (pointMul crv vBlind h) (pointBaseMul crv (toInteger v))) <$> (take 32 $ zip vs vBlinds)
    range_proof <- generate_range_proof ub (take 1 vs) (take 1 vBlinds) h
    range_proof2 <- generate_range_proof ub (take 2 vs) (take 2 vBlinds) h
    range_proof8 <- generate_range_proof ub (take 8 vs) (take 8 vBlinds) h
    range_proof16 <- generate_range_proof ub (take 16 vs) (take 16 vBlinds) h
    range_proof32 <- generate_range_proof ub (take 32 vs) (take 32 vBlinds) h

    
    defaultMain [
        bgroup "BulletProof Range Proof" [
            bench "Verifying 1 x 64-bit rangeproof" $ nf (\x -> verify_range_proof x commV h) range_proof,
            bench "Verifying 2 x 64-bit rangeproof" $ nf (\x -> verify_range_proof x commVs2 h) range_proof2,
            bench "Verifying 8 x 64-bit rangeproof" $ nf (\x -> verify_range_proof x commVs8 h) range_proof8,
            bench "Verifying 16 x 64-bit rangeproof" $ nf (\x -> verify_range_proof x commVs16 h) range_proof16,
            bench "Verifying 32 x 64-bit rangeproof" $ nf (\x -> verify_range_proof x commVs32 h) range_proof32
        ]
        ]