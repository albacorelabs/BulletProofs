{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE ApplicativeDo #-}
module RangeProof where

import Utils
import InnerProductProof

import Crypto.PubKey.ECC.Generate
import Crypto.PubKey.ECC.Prim
import Crypto.PubKey.ECC.Generate
import Crypto.PubKey.ECC.Types
import Data.Bits
import Data.Int

import Crypto.Hash
import Crypto.Number.Serialize
import Crypto.Number.ModArithmetic

import Data.ByteString (ByteString)
import qualified Data.Serialize as S
import GHC.Generics

data RangeProof = RangeProof{
    commitA :: Point,
    commitS :: Point,
    commitT1 :: Point,
    commitT2 :: Point,
    taux :: Integer,
    mu :: Integer,
    tx :: Integer,
    ipp :: InnerProductProof,
    n :: Integer
} deriving (Show, Generic, S.Serialize)

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
    print verified


generate_range_proof :: Int -> [Integer] -> [Integer] -> Point -> Point -> IO RangeProof
generate_range_proof upperBound vs vBlinds pub rp  = do
    -- Setup necessary blinding factors
    alpha <- scalarGenerate crv
    rho   <- scalarGenerate crv
    tau1  <- scalarGenerate crv
    tau2  <- scalarGenerate crv

    let al = foldr1 (++) $ (\v -> [if testBit v i then 1 else 0 | i <- [0.. (upperBound -1)]]) <$> vs
        m = fromIntegral $ length vs -- number of range proofs
        n = fromIntegral $ (fromIntegral  (length al)) `div` m -- length of each range proof
        ar = al .-. (1 `vectorPow` (n*m))
        gs = perturbBase (n*m)
        hs = perturbH rp (n*m)
    sl <- replicate (length al) <$> scalarGenerate crv
    sr <- replicate (length ar) <$> scalarGenerate crv

        -- Commitment to al and ar
    let commitA = foldr1 (pointAdd crv) [pointMul crv alpha pub, al `ecInner` gs, ar `ecInner` hs ]
        -- Commitment to blinding factors sl and sr
        commitS = foldr1 (pointAdd crv) [pointMul crv rho pub, sl `ecInner` gs , sr `ecInner` hs]

        y = (parseHexHash $ hashFinalize $ hashUpdates hashInit $ pointToByte <$> [commitA,commitS]) `mod` q
        z = (parseHexHash $ hashFinalize $ hashUpdates hashInit $ [pointToByte commitA,pointToByte commitS,i2osp y]) `mod` q

        -- Setup l = (al - z*(1^n)) + sl*X
        l0 = al .-. ((*z) <$> 1 `vectorPow` (n*m))
        l1 = sl

        -- Setup r = y^n `hadamard` (ar + z*(1^n) + sr*x) + z^2*2^n
        cat_terms j = (0 `vectorPow` ((j-1)*n) ++ 2 `vectorPow` n ++ 0 `vectorPow` ((m-j)*n))
        r0_aggterm = foldr1 (.+.) $ (\j -> (*) (z^(1+j)) <$> cat_terms j) <$> [1..m]
        r0 = r0_aggterm .+. ((y `vectorPow` (n*m)) .*. (ar .+. ((*z) <$> (1 `vectorPow` (n*m)))))
        r1 = sr .*. (y `vectorPow` (n*m))

        -- Setup t(x) = <l,r> = t0 + t1*x + t2*x^2
        -- Karatsuba -> t2 = l1 * r1 , t1 = l1 * r0 + r1 * l0 , t0 = l0 * r0
        t2 = l1 `vectorInner` r1 
        t1 = (l1 `vectorInner` r0) + (r1 `vectorInner` l0)
        t0 = l0 `vectorInner` r0

        commitT1 = pointAdd crv (pointMul crv tau1 pub) (pointBaseMul crv t1)
        commitT2 = pointAdd crv (pointMul crv tau2 pub) (pointBaseMul crv t2)

        x = (parseHexHash $ hashFinalize $ hashUpdates hashInit $ [pointToByte commitA,pointToByte commitS,i2osp y,i2osp z,pointToByte commitT1,pointToByte commitT2]) `mod` q

        --Finalise l(x), r(x) & t(x)
        lx = l0 .+. ((*x) <$> l1)
        rx = r0 .+. ((*x) <$> r1)
        tx = (t0 + t1*x + t2*x*x) `mod` q

        -- Setup tau(x) = tau2 *x^2 + tau1*x + z^2*vBlind && mu = alpha + rho*x
        agg_tau0 = sum $ (\(j,vBlind) -> z^(1+j) * vBlind) <$> zip [1..m] vBlinds
        tau = (tau2*x*x + tau1*x + agg_tau0) `mod` q
        mu = (alpha + rho*x) `mod` q

        x_prot_1 = (parseHexHash $ hashFinalize $ hashUpdates hashInit ([i2osp tau,i2osp mu, i2osp tx ] :: [ByteString])) `mod` q
        gx = pointBaseMul crv x_prot_1

        invY = (\i -> expSafe y (-i) q) <$> [0..(m*n-1)]
        hs' = zipWith (pointMul crv) invY hs
        
        commit = foldr1 (pointAdd crv) [pointMul crv tx gx, lx `ecInner` gs, rx `ecInner` hs']

        ipp = generate_inner_product_proof gs hs' gx commit lx rx
    return $ RangeProof commitA commitS commitT1 commitT2 tau mu tx ipp n


verify_range_proof :: RangeProof -> [Point] -> Point -> Point -> Bool
verify_range_proof RangeProof{..} commitLR pub rp = verifiedComm && ipVerify
    where
        y = (parseHexHash $ hashFinalize $ hashUpdates hashInit $ pointToByte <$> [commitA,commitS]) `mod` q
        z = (parseHexHash $ hashFinalize $ hashUpdates hashInit $ [pointToByte commitA,pointToByte commitS,i2osp y]) `mod` q
        x = (parseHexHash $ hashFinalize $ hashUpdates hashInit $ [pointToByte commitA,pointToByte commitS,i2osp y,i2osp z,pointToByte commitT1,pointToByte commitT2]) `mod` q


        -- Check commLR is the commitment to V -> tG + tauxH = z^2*V + deltaG + xT1 + x^2T2
        -- delta = (z- z^2)*(1^n * y^n ) - z^3(1^n * 2^n)
        m = fromIntegral $ length commitLR
        tG = pointBaseMul crv tx 
        tauxH = pointMul crv taux pub
        agg_delta = sum $ (\j -> (*) (z^(j+2)) ( (1 `vectorPow` (n)) `vectorInner` (2 `vectorPow` (n)) )) <$> [1..m]
        delta = ((z - z*z)*((1 `vectorPow` (n*m)) `vectorInner` (y `vectorPow` (n*m))) - agg_delta) `mod` q
        rhs = foldr1 (pointAdd crv) [((*) (z*z) <$> (z `vectorPow` m)) `ecInner` commitLR, pointBaseMul crv delta,pointMul crv x commitT1, pointMul crv (x*x) commitT2]
        verifiedComm = rhs == (pointAdd crv tG tauxH)


        -- Check A & S commitments -> A + xS - zG + (z*y^n + z^2*2^n) H' = muH + lG + rH'
        invY = (\i -> expSafe y (-i) q) <$> [0..(m*n-1)]
        gs = perturbBase $ m*n 
        hs = perturbH rp $ m*n  
        hs' = zipWith (pointMul crv) invY hs
        x_prot_1 = (parseHexHash $ hashFinalize $ hashUpdates hashInit ([i2osp taux,i2osp mu, i2osp tx ] :: [ByteString])) `mod` q
        gx = pointBaseMul crv x_prot_1
        
        partHs :: Int -> Int -> [Point]
        partHs n j = drop ((j - 1) * n) $ take (j *n)  hs'

        aggFactor = foldr1 (pointAdd crv) $ (\j -> ((*) (z^(j+1)) <$> (2 `vectorPow` n)) `ecInner` (partHs (fromInteger n) (fromInteger j)) ) <$> [1..m]

        pLHS = foldr1 (pointAdd crv) [commitA, pointMul crv x commitS,         
               pointNegate crv $ ((*z) <$> 1 `vectorPow` (n*m)) `ecInner` gs,
               ((*z) <$> (y `vectorPow` (n*m))) `ecInner` hs', aggFactor]

        pNoMu = foldr1 (pointAdd crv) [pointMul crv tx gx,pLHS,pointNegate crv $ pointMul crv mu pub]
        ipVerify = verify_inner_product (n*m) gs hs' pNoMu ipp