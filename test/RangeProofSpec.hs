module RangeProofSpec where

import RangeProof
import Utils

import Crypto.PubKey.ECC.Prim 
import Crypto.PubKey.ECC.Types
import Crypto.PubKey.ECC.Generate (generateQ)
import Data.Int
import Test.QuickCheck
import Test.QuickCheck.Monadic
import Test.Hspec

import Control.Monad.IO.Class

spec :: Spec
spec = do
    describe "Checking correctness of range proof" $ do
        it "Checking that a range proof is correct is in the range" $ do
            property $ quickCheckWith stdArgs {maxSuccess =1000} prop_checkRangeProof


instance Arbitrary Point where
    arbitrary = do
        i <- arbitrary 
        return $ generateQ crv i
        

prop_checkRangeProof :: Positive Int64 -> Positive Integer -> Point -> Point -> Property
prop_checkRangeProof v vBlind h rp  = monadicIO $ do
    let commV = pointAdd crv (pointMul crv (getPositive vBlind) h) (pointBaseMul crv (toInteger (getPositive v)))
    range_proof <- run $ generate_range_proof (getPositive v) (getPositive vBlind) h rp
    verified <- run $ verify_range_proof range_proof commV h rp
    assert $ True == verified


