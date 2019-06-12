module PippengerSpec where

import EC_Mult
import Utils
import Constants

import Crypto.PubKey.ECC.Prim 
import Crypto.PubKey.ECC.Types
import Crypto.PubKey.ECC.Generate (generateQ)
import Test.QuickCheck
import Test.QuickCheck.Gen
import Test.Hspec

import Control.Monad.IO.Class

spec :: Spec
spec = do
    describe "Checking correctness of Pippenger's Algorithm" $ do
        it "Comparing to basic multiplication" $ do
            quickCheckWith stdArgs {maxSuccess =100} prop_checkSmallPippenger
            quickCheckWith stdArgs {maxSuccess =100} prop_checkLargePippenger
            quickCheckWith stdArgs {maxSuccess =20} prop_checkBigArrPippenger


newtype BigInt = BigInt {getBig :: Integer} deriving (Show)
newtype LargeArray a = LargeArray {extractArr :: [a]} deriving (Show)

instance Arbitrary BigInt where
    arbitrary = do
        expo <- choose (100,200) :: Gen Integer
        return $ BigInt (2^expo)

instance Arbitrary Point where
    arbitrary = do
        i <- arbitrary 
        return $ generateQ crv i

instance (Arbitrary a) => Arbitrary (LargeArray a) where
    arbitrary = do
        length <- choose (500,900) :: Gen Int
        arr <- vectorOf length arbitrary
        return $ LargeArray arr
        
prop_checkSmallPippenger :: [Positive Integer] -> Point -> Bool
prop_checkSmallPippenger [] _ = discard
prop_checkSmallPippenger v pt = naive == pipp
    where
        posV = getPositive <$> v
        naive = foldr1 (pointAdd crv) $ (\i -> pointMul crv i pt) <$> posV
        pipp = pippenger $ zip posV $ repeat pt

prop_checkLargePippenger :: [BigInt] -> Point -> Bool
prop_checkLargePippenger [] _ = discard
prop_checkLargePippenger v pt = naive == pipp
    where
        posV = getBig <$> v
        naive = foldr1 (pointAdd crv) $ (\i -> pointMul crv i pt) <$> posV
        pipp = pippenger $ zip posV $ repeat pt

prop_checkBigArrPippenger :: LargeArray BigInt -> Point -> Bool
prop_checkBigArrPippenger v pt = naive == pipp
    where
        posV = getBig <$> (extractArr v)
        naive = foldr1 (pointAdd crv) $ (\i -> pointMul crv i pt) <$> posV
        pipp = pippenger $ zip posV $ repeat pt
