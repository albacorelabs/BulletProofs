module UtilsSpec where

import Test.QuickCheck
import Test.QuickCheck.Modifiers
import Test.QuickCheck.Monadic
import Test.Hspec
import Test.Hspec.Core.QuickCheck (modifyMaxSuccess)

import Utils
import Crypto.PubKey.ECC.Types
import Crypto.PubKey.ECC.Generate

instance Arbitrary Point where
    arbitrary = do
        i <- arbitrary
        return $ generateQ crv i

spec :: Spec
spec = do
    describe "Checking correctness point compressions" $ do
        modifyMaxSuccess (const 1000) $ it "decompressing a compressed point is an identity operation" $ do
            property prop_checkCompressDecompress
        

prop_checkCompressDecompress :: Point -> Bool
prop_checkCompressDecompress PointO = discard
prop_checkCompressDecompress point= point == (decompressPoint crv . compressPoint) point