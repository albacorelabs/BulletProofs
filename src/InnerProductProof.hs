{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ApplicativeDo #-}

module InnerProductProof where

import Crypto.PubKey.ECC.Prim
import Crypto.PubKey.ECC.Generate
import Crypto.PubKey.ECC.Types
import Crypto.Number.ModArithmetic
import Crypto.Hash

import qualified Data.ByteString.Char8 as B8
import Data.List (foldl')

import Utils

data InnerProductProof = InnerProductProof{
    h :: Point,
    lVector :: [Integer],
    rVector :: [Integer],
    lTerms :: [Point],
    rTerms :: [Point]
} deriving (Show)

run_Proof :: IO ()
run_Proof = do
    let crv = getCurveByName SEC_p256k1
    h <- generateQ crv <$> scalarGenerate crv
    let q = ecc_n $ common_curve crv
        a = [10,2]
        b = [5,4]
        z = (a `vectorInner` b) `mod` q
        n = fromIntegral $ length a
        inner = ecInner crv
        commit = foldr1 (pointAdd crv) [pointBaseMul crv z, a `inner` perturbBase crv n, b `inner` perturbH crv h n]
        x = 3
        y = 4
    proof <- generate_inner_product_proof crv h commit a b x y
    print proof
    booly <- verify_inner_product n crv h commit proof z x y
    print booly

    

generate_inner_product_proof :: Curve -> Point -> Point -> [Integer] -> [Integer] -> Integer -> Integer -> IO InnerProductProof
generate_inner_product_proof crv h commit lVector rVector x y = mk_inner_product_proof crv h commit lVector rVector [] [] x y

--- Prove  C = aG + bH + <a,b>Q 
--- In compressed form: C' = a'G' + b'H' + <a',b'>Q = C + x^2L + x(-2)R 
mk_inner_product_proof :: Curve -> Point -> Point -> [Integer] -> [Integer] -> [Point] -> [Point] -> Integer -> Integer -> IO InnerProductProof
mk_inner_product_proof _ _ _ [] [] _ _ _ _ = return $ InnerProductProof PointO [] [] [] []
mk_inner_product_proof crv h commitLR [a] [b] lTerms rTerms x y = return $ InnerProductProof h [a] [b] lTerms rTerms
mk_inner_product_proof crv h commitLR lVector rVector  lTerms rTerms x y = do
    mk_inner_product_proof crv h commit' a' b' (lTerm:lTerms) (rTerm:rTerms) x y
    where
        -- Curry some useful functions until i extract curve
        inner = ecInner crv 
        hadamard = ecHadamard crv

        q = ecc_n $ common_curve crv
        n = fromIntegral $ length lVector
        n' = n `div` 2

        -- vectors of H's and G's 
        hs = perturbH crv h n
        gs = perturbBase crv n

        -- Vector Cuts
        (aLo,aHi) = splitAt (fromInteger n') lVector
        (bLo,bHi) = splitAt (fromInteger n') rVector
        (gLo,gHi) = splitAt (fromInteger n') gs
        (hLo,hHi) = splitAt (fromInteger n') hs

        -- L & R components from the inner product z (tx)
        zl = pointBaseMul crv (aLo `vectorInner` bHi)
        zr = pointBaseMul crv (aHi `vectorInner` bLo)

        -- Leftover terms from inner product a', b' and <a',b'>
        -- lTerm = L(a') + L(b') + L(<a',b'>)
        -- rTerm = R(a') + R(b') + R(<a',b'>)
        lTerm = foldr1 (pointAdd crv) [(aLo `inner` gHi),(bHi `inner` hLo),zl]
        rTerm = foldr1 (pointAdd crv) [(aHi `inner` gLo), (bLo `inner` hHi),zr]

        -- Fiat Shamir x and x inverse
        -- x = parseHexHash $ hashFinalize $ hashUpdates hashInit $ pointToByte <$> [commitLR,lTerm,rTerm]
        invX = expFast x (-1) q

        -- x^2L && x^(-2)R
        xlTerm = pointMul crv (x*x) lTerm
        xrTerm = pointMul crv (invX * invX) rTerm
        
        -- Condensed vector as part of the `stack` portion of the cut - n -stack
        a' = ((*x) <$> aLo) .+. ((*invX) <$> aHi)
        b' = ((*invX) <$> bLo) .+. ((*x) <$> bHi)

        -- Condensed Point Terms from cut - n - stack
        gs' = zipWith (pointAdd crv) (pointMul crv x <$> gHi) (pointMul crv invX <$> gLo)
        hs' = zipWith (pointAdd crv) (pointMul crv invX <$> hHi) (pointMul crv x <$> hLo)
        
        -- Condensed Inner Product z' = <a',b'> and C' = z'G + a'G' + b'H'
        z' = (a' `vectorInner` b') `mod` q
        commit' = foldr1 (pointAdd crv) [pointBaseMul crv z',a' `inner` gs',b' `inner` hs'] -- z'Q + a'G' + b'H'

verify_inner_product :: Integer -> Curve -> Point -> Point -> InnerProductProof -> Integer -> Integer -> Integer -> IO Bool
verify_inner_product n crv h' commitLR ip@InnerProductProof{..} tx x y = do
    return $ commit' == commitO
    where
        -- (xs,xsInv,cc) = generate_shamir_xs ip commitLR
        
        inner = ecInner crv
        g' = mkExponents n crv (perturbBase crv n) x
        q = ecc_n $ common_curve crv
        
        hs = perturbH crv h n 
        h' = mkExponents n crv (reverse hs) x
        invX = expFast x (-1) q

        aG' = pointMul crv (head lVector) g'
        bH' = pointMul crv (head rVector) h'
        tx' = (lVector `vectorInner` rVector) `mod` q
        
        lTerm = pointMul crv (x*x) $ head lTerms
        rTerm = pointMul crv (invX * invX) $ head rTerms
        
        commit' = foldr1 (pointAdd crv) [pointBaseMul crv tx', lVector `inner` [g'],rVector `inner` [h']] -- z'G + a'G' + b'H'
        commitO = foldr1 (pointAdd crv) [commitLR,lTerm,rTerm] -- (tx)G + lG + rH + x^2L   + x^(-2)R 

mkExponents :: Integer -> Curve -> [Point] -> Integer -> Point
mkExponents n crv [g] _ = g
mkExponents n crv gs  x = mkExponents n' crv g' x
    where
        n' = fromInteger (n `div` 2)
        (gLo,gHi) = splitAt (fromInteger n') $ take (fromInteger n) gs
        q = ecc_n $ common_curve crv
        invX = expSafe x (-1) q
        g' = zipWith (pointAdd crv) (pointMul crv x <$> gHi) (pointMul crv invX <$> gLo)


-- generate_shamir_xs :: InnerProductProof -> Point -> ([Integer], [Integer], Point)
-- generate_shamir_xs InnerProductProof{..} commitLR =
--     foldl' ( \(xs, xsInv, cc) (left,right) -> 
--         let x = parseHexHash $ hashFinalize $ hashUpdates hashInit $ pointToByte <$> [cc,left,right]
--             xInv = expSafe x (-1) q
--             c = foldr1 (pointAdd crv) [pointMul crv (x*x) $ left,pointMul crv (xInv*xInv) $ right, cc]
--         in (x:xs, xInv:xsInv, c)
--         ) ([] , [], commitLR) $ zip lTerms rTerms

