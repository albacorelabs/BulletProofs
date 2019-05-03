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
    let vBlind = 10
        v = 8
        commV = pointAdd crv (pointMul crv vBlind h) (pointBaseMul crv (toInteger v))
    range_proof <- generate_range_proof v vBlind h rp
    let curriedVerify = (\x -> verify_range_proof x commV h rp)
    -- verified <- verify_range_proof range_proof commV h rp
    
    defaultMain [
        bgroup "BulletProof Range Proof" [
            bench "Verifying 64-bit rangeproof" $ nfIO $ curriedVerify range_proof
            ]
        ]