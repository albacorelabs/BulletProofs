{-# LANGUAGE ScopedTypeVariables #-}
module RangeProofSpec where

import RangeProof
import Utils
import Constants

import Crypto.PubKey.ECC.Prim 
import Crypto.PubKey.ECC.Types
import Crypto.PubKey.ECC.Generate (generateQ)
import Data.Int
import Test.QuickCheck
import Test.QuickCheck.Modifiers
import Test.QuickCheck.Monadic
import Test.Hspec
import Test.Hspec.Core.QuickCheck (modifyMaxSuccess)


import Control.Monad.IO.Class

spec :: Spec
spec = do
    describe "Checking correctness of range proof" $ do
        modifyMaxSuccess (const 10) $ it "Check proof that value (v) is in the range (0,2^n]" $ do
            property prop_checkRangeProof
        modifyMaxSuccess (const 10) $ it "Check aggregated range proofs" $ do    
            property prop_checkAggRangeProof
        it "Failing Test range proof for the number 256 with an 8-bit upper limit returns false" $ do
            run_OOBRangeProof `shouldReturn` False 


data VAndVBlinds = VAndVBlinds {
    vvBlind :: (Integer,Integer)
} deriving (Show)
    
instance Arbitrary Point where
    arbitrary = do
        i <- arbitrary 
        return $ generateQ crv (i `mod` (ecc_n $ common_curve crv)) 

instance Arbitrary VAndVBlinds where
    arbitrary = do
        Positive v <- arbitrary 
        Positive vBlind <- arbitrary 
        return $ VAndVBlinds $ (v,vBlind)

data ListPow2 a = ListPow2 {
    unwrapListPow2 :: [a]
} deriving (Show)

instance Arbitrary a => Arbitrary (ListPow2 a ) where
    arbitrary = do
        n <- arbitrary `suchThat` (>0) :: Gen Int
        list <- vectorOf (2^(n `mod` 3)) arbitrary
        return $ ListPow2 list
  
        
prop_checkRangeProof ::  Positive Integer ->  Positive Integer -> Point -> Property
prop_checkRangeProof v vBlind h  = monadicIO $ do
    let vs = [v]
        vBlinds = [vBlind]
        commV = (\ (v,vBlind) -> pointAdd crv (pointMul crv (getPositive vBlind) h) (pointBaseMul crv (toInteger (getPositive v)))) <$> zip vs vBlinds
        ub = max 8 $ (ceiling . logBase 2.0 . fromIntegral . getPositive) v
    range_proof <- run $ generate_range_proof ub (getPositive <$> vs) (getPositive <$> vBlinds) h
    let verified =  verify_range_proof range_proof commV h
    assert $ True == verified

prop_checkAggRangeProof :: ListPow2 VAndVBlinds -> Point -> Property
prop_checkAggRangeProof varr h  = monadicIO $ do
    let vvblind = vvBlind <$> unwrapListPow2 varr
        commV = (\ (v,vBlind) -> pointAdd crv (pointMul crv vBlind h) (pointBaseMul crv (toInteger v))) <$> vvblind
        vs = fst <$> vvblind
        vBlinds = snd <$> vvblind
        uB = max 8 $ maximum $ ((ceiling . (logBase 2.0) . fromIntegral) <$> (fst <$> vvblind))
    range_proof <- run $ generate_range_proof uB vs vBlinds h
    let verified =  verify_range_proof range_proof commV h
    assert $ True == verified
 
run_OOBRangeProof :: IO Bool
run_OOBRangeProof = do
    h <- generateQ crv <$> scalarGenerate crv
    let vBlinds = [10,12]
        vs = [256,9]
        commVs =  (\ (v,vBlind) -> pointAdd crv (pointMul crv vBlind h) (pointBaseMul crv (toInteger v))) <$> zip vs vBlinds
        uB = 8 -- # of Bits vs needs to below
    range_proof <- generate_range_proof uB vs vBlinds h
    return $ verify_range_proof range_proof commVs h