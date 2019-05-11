{-# LANGUAGE ScopedTypeVariables #-}
module RangeProofSpec where

import RangeProof
import Utils

import Crypto.PubKey.ECC.Prim 
import Crypto.PubKey.ECC.Types
import Crypto.PubKey.ECC.Generate (generateQ)
import Data.Int
import Test.QuickCheck
import Test.QuickCheck.Modifiers
import Test.QuickCheck.Monadic
import Test.Hspec

import Control.Monad.IO.Class

spec :: Spec
spec = do
    describe "Checking correctness of range proof" $ do
        it "Check proof that value (v) is in the range (0,2^n]" $ do
            property $ quickCheckWith stdArgs {maxSuccess =10} prop_checkRangeProof
        it "Check aggregated range proofs" $ do    
            property $ quickCheckWith stdArgs {maxSuccess =10} prop_checkAggRangeProof


data VAndVBlinds = VAndVBlinds {
    vvBlind :: (Int64,Integer)
} deriving (Show)
    
instance Arbitrary Point where
    arbitrary = do
        i <- arbitrary 
        return $ generateQ crv i

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
  
        
prop_checkRangeProof ::  Positive Int64 ->  Positive Integer -> Point -> Point -> Property
prop_checkRangeProof v vBlind h rp  = monadicIO $ do
    let vs = [v]
        vBlinds = [vBlind]
        commV = (\ (v,vBlind) -> pointAdd crv (pointMul crv (getPositive vBlind) h) (pointBaseMul crv (toInteger (getPositive v)))) <$> zip vs vBlinds
    range_proof <- run $ generate_range_proof (getPositive <$> vs) (getPositive <$> vBlinds) h rp
    let verified =  verify_range_proof range_proof commV h rp
    assert $ True == verified

-- prop_checkAggRangeProof :: NonEmptyList (Positive Int64) -> NonEmptyList (Positive Integer) -> Point -> Point -> Property
prop_checkAggRangeProof :: ListPow2 VAndVBlinds -> Point -> Point -> Property
prop_checkAggRangeProof varr h rp  = monadicIO $ do
    let vvblind = vvBlind <$> unwrapListPow2 varr
        commV = (\ (v,vBlind) -> pointAdd crv (pointMul crv vBlind h) (pointBaseMul crv (toInteger v))) <$> vvblind
        vs = fst <$> vvblind
        vBlinds = snd <$> vvblind
    range_proof <- run $ generate_range_proof vs vBlinds h rp
    let verified =  verify_range_proof range_proof commV h rp
    assert $ True == verified


-- failingTest :: [Int64] -> [Integer]
-- failingTest v vBlinds
--     v = [9,7,7,6,5,9,6,9,2,10]
--     v = [9,7,7,6,5,9,6,9,2,10]