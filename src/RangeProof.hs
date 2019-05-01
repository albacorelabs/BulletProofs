{-# LANGUAGE RecordWildCards #-}
module RangeProof where

import Utils
import Crypto.PubKey.ECC.Generate
import Crypto.PubKey.ECC.Prim
import Crypto.PubKey.ECC.Generate
import Crypto.PubKey.ECC.Types
import Data.Bits
import Data.Int

import Crypto.Hash
import Crypto.Number.Serialize
import Crypto.Number.ModArithmetic

data RangeProof = RangeProof{
    commitA :: Point,
    commitS :: Point,
    commitT1 :: Point,
    commitT2 :: Point,
    taux :: Integer,
    mu :: Integer,
    tx :: Integer,
    lx :: [Integer],
    rx :: [Integer],
    n :: Integer
} deriving (Show)

run_rangeProof :: IO ()
run_rangeProof = do
    h <- generateQ crv <$> scalarGenerate crv
    rp <- generateQ crv <$> scalarGenerate crv
    let vBlind = 10
        v = 8
        commV = pointAdd crv (pointMul crv vBlind h) (pointBaseMul crv (toInteger v))
    range_proof <- generate_range_proof v vBlind h rp
    verified <- verify_range_proof range_proof commV h rp
    print verified


generate_range_proof :: Int64 -> Integer -> Point -> Point -> IO RangeProof
generate_range_proof v vBlind pub rp  = do
    -- Setup necessary blinding factors
    alpha <- scalarGenerate crv
    rho   <- scalarGenerate crv
    tau1  <- scalarGenerate crv
    tau2  <- scalarGenerate crv

    let al = [if testBit v i then 1 else 0 | i <- [0.. (finiteBitSize v -1)]]
        n = fromIntegral $ length al
        ar = al .-. (1 `vectorPow` n)
        gs = perturbBase n
        hs = perturbH rp n
    sl <- replicate (length al) <$> scalarGenerate crv
    sr <- replicate (length ar) <$> scalarGenerate crv

        -- Commitment to al and ar
    let commitA = foldr1 (pointAdd crv) [pointMul crv alpha pub, al `ecInner` gs, ar `ecInner` hs ]
        -- Commitment to blinding factors sl and sr
        commitS = foldr1 (pointAdd crv) [pointMul crv rho pub, sl `ecInner` gs , sr `ecInner` hs]

        y = (parseHexHash $ hashFinalize $ hashUpdates hashInit $ pointToByte <$> [commitA,commitS]) `mod` q
        z = (parseHexHash $ hashFinalize $ hashUpdates hashInit $ [pointToByte commitA,pointToByte commitS,i2osp y]) `mod` q

        -- Setup l = (al - z*(1^n)) + sl*X
        l0 = al .-. ((*z) <$> 1 `vectorPow` n)
        l1 = sl

        -- Setup r = y^n `hadamard` (ar + z*(1^n) + sr*x) + z^2*2^n
        r0 = ((* (z*z)) <$> (2 `vectorPow` n)) .+. ((y `vectorPow` n) .*. (ar .+. ((*z) <$> (1 `vectorPow` n))))
        r1 = sr .*. (y `vectorPow` n)

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
        tau = (tau2*x*x + tau1*x + z*z*vBlind) `mod` q
        mu = (alpha + rho*x) `mod` q

    return $ RangeProof commitA commitS commitT1 commitT2 tau mu tx lx rx n


verify_range_proof :: RangeProof -> Point -> Point -> Point -> IO Bool
verify_range_proof RangeProof{..} commitLR pub rp = do
    return $ verifiedComm && verifiedAS && verifiedTx
    where
        y = (parseHexHash $ hashFinalize $ hashUpdates hashInit $ pointToByte <$> [commitA,commitS]) `mod` q
        z = (parseHexHash $ hashFinalize $ hashUpdates hashInit $ [pointToByte commitA,pointToByte commitS,i2osp y]) `mod` q
        x = (parseHexHash $ hashFinalize $ hashUpdates hashInit $ [pointToByte commitA,pointToByte commitS,i2osp y,i2osp z,pointToByte commitT1,pointToByte commitT2]) `mod` q


        -- Check commLR is the commitment to V -> tG + tauxH = z^2*V + deltaG + xT1 + x^2T2
        -- delta = (z- z^2)*(1^n * y^n ) - z^3(1^n * 2^n)
        tG = pointBaseMul crv tx 
        tauxH = pointMul crv taux pub
        delta = ((z - z*z)*((1 `vectorPow` n) `vectorInner` (y `vectorPow` n)) - ((z*z*z)*(1 `vectorPow` n) `vectorInner` (2 `vectorPow`n) )) `mod` q
        rhs = foldr1 (pointAdd crv) [pointMul crv (z*z) commitLR, pointBaseMul crv delta,pointMul crv x commitT1, pointMul crv (x*x) commitT2]
        verifiedComm = rhs == (pointAdd crv tG tauxH)


        -- Check A & S commitments -> A + xS - zG + (z*y^n + z^2*2^n) H' = muH + lG + rH'
        invY = (\i -> expSafe y (-i) q) <$> [0..(n-1)]
        gs = perturbBase n 
        hs = perturbH rp n 
        hs' = zipWith (pointMul crv) invY hs
        hFactor = (.+.) ((*z) <$> (y `vectorPow` n)) $ ((*) (z*z) <$> (2 `vectorPow` n))
    
        pLHS = foldr1 (pointAdd crv) [commitA, pointMul crv x commitS,         
               pointNegate crv $ ((*z) <$> 1 `vectorPow` n) `ecInner` gs,
               hFactor `ecInner` hs']
               
        pRHS = foldr1 (pointAdd crv) [pointMul crv mu pub, lx `ecInner` gs, rx `ecInner` hs']

        verifiedAS = pLHS == pRHS

        -- Check tx = <l,r>
        tx' = (lx `vectorInner` rx) `mod` q
        verifiedTx = tx' == tx
