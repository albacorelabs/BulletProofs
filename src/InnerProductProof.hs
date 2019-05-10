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
        a = [10,2,10,2,10,2,10,2,10,2,10,2,10,2,10,2,10,2,10,2,10,2,10,2,10,2,10,2,10,2,10,2]
        b = [5,4,10,2,10,2,10,2,10,2,10,2,10,2,10,2,5,4,10,2,10,2,10,2,10,2,10,2,10,2,10,2]
        z = (a `vectorInner` b) `mod` q
        n = fromIntegral $ length a
        commit = foldr1 (pointAdd crv) [pointMul crv z h, a `ecInner` perturbBase n, b `ecInner` perturbH h n]
        hs = perturbH h n
        gs = perturbBase n
        proof = generate_inner_product_proof gs hs h commit a b
        booly = verify_inner_product n gs hs commit proof
        
    print booly

    

generate_inner_product_proof :: [Point] -> [Point] -> Point -> Point -> [Integer] -> [Integer] -> InnerProductProof
generate_inner_product_proof gs hs h commit lVector rVector = mk_inner_product_proof gs hs h commit lVector rVector [] []

--- Prove  C = aG + bH + <a,b>Q 
--- In compressed form: C' = a'G' + b'H' + <a',b'>Q = C + x^2L + x(-2)R 
mk_inner_product_proof :: [Point] -> [Point] -> Point -> Point -> [Integer] -> [Integer] -> [Point] -> [Point] -> InnerProductProof
mk_inner_product_proof  _   _ _    _    [] [] _ _ = InnerProductProof PointO [] [] [] []
mk_inner_product_proof gs hs h commitLR [a] [b] lTerms rTerms = InnerProductProof h [a] [b] (reverse lTerms) $ reverse rTerms
mk_inner_product_proof gs hs h commitLR lVector rVector  lTerms rTerms = mk_inner_product_proof gs' hs' h commit' a' b' (lTerm:lTerms) (rTerm:rTerms)
    where
        q = ecc_n $ common_curve crv
        n = fromIntegral $ length lVector
        n' = n `div` 2

        -- Vector Cuts
        (aLo,aHi) = splitAt (fromInteger n') lVector
        (bLo,bHi) = splitAt (fromInteger n') rVector
        (gLo,gHi) = splitAt (fromInteger n') gs
        (hLo,hHi) = splitAt (fromInteger n') hs

        -- L & R components from the inner product z (tx)
        zl = pointMul crv (aLo `vectorInner` bHi) h 
        zr = pointMul crv (aHi `vectorInner` bLo) h

        -- Leftover terms from inner product a', b' and <a',b'>
        -- lTerm = L(a') + L(b') + L(<a',b'>)
        -- rTerm = R(a') + R(b') + R(<a',b'>)
        lTerm = foldr1 (pointAdd crv) [(aLo `ecInner` gHi),(bHi `ecInner` hLo),zl]
        rTerm = foldr1 (pointAdd crv) [(aHi `ecInner` gLo), (bLo `ecInner` hHi),zr]

        -- Fiat Shamir x and x inverse
        x = (parseHexHash $ hashFinalize $ hashUpdates hashInit $ pointToByte <$> [commitLR,lTerm,rTerm]) `mod` q
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
        commit' = foldr1 (pointAdd crv) [commitLR,xlTerm,xrTerm] -- this calcs faster than using z'Q + a'G' + b'H'


verify_inner_product :: Integer -> [Point] -> [Point] -> Point -> InnerProductProof -> Bool
verify_inner_product n gs hs commitLR ip@InnerProductProof{..} = commit' == commitO
    where
        (x,commitO) = foldl' (\(xs,commit) (lTerm,rTerm)  -> 
                let fshX = (parseHexHash $ hashFinalize $ hashUpdates hashInit $ pointToByte <$> [commit,lTerm,rTerm]) `mod` q
                    commit' = calc_final_commit crv commit [fshX] [lTerm] [rTerm]
                in (fshX:xs, commit')
            ) ([],commitLR) (zip lTerms rTerms) 
        
        g' = mkExponents n crv gs $ reverse x
        q = ecc_n $ common_curve crv
        
        h' = mkExponents n crv (reverse hs) $ reverse x
        invX = (\xs -> expFast xs (-1) q) <$> x

        tx' = (lVector `vectorInner` rVector) `mod` q
                
        commit' = foldr1 (pointAdd crv) [pointMul crv tx' h, lVector `ecInner` [g'],rVector `ecInner` [h']] -- z'G + a'G' + b'H'

mkExponents :: Integer -> Curve -> [Point] -> [Integer] -> Point
mkExponents n crv [g] [] = g
mkExponents n crv gs  (x:xs) = mkExponents n' crv g' xs
    where
        n' = fromInteger (n `div` 2)
        (gLo,gHi) = splitAt (fromInteger n') $ take (fromInteger n) gs
        q = ecc_n $ common_curve crv
        invX = expSafe x (-1) q
        g' = zipWith (pointAdd crv) (pointMul crv x <$> gHi) (pointMul crv invX <$> gLo)

calc_final_commit :: Curve -> Point -> [Integer] -> [Point] -> [Point] -> Point
calc_final_commit _ commitLR _ [] [] =  commitLR
calc_final_commit crv commitLR (x:xs) (lt:lts) (rt:rts) = calc_final_commit crv commitO xs lts rts
    where
        q = ecc_n $ common_curve crv
        invX = expFast x (-1) q
        lTerm = pointMul crv (x*x) $ lt
        rTerm = pointMul crv (invX * invX) $ rt
        commitO = foldr1 (pointAdd crv) [commitLR,lTerm,rTerm]
