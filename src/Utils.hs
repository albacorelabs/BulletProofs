{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Utils where

import Data.Char
import Crypto.PubKey.ECC.Prim
import Crypto.PubKey.ECC.Types
import Data.List (foldl')
import qualified Data.ByteArray as B
import qualified Data.ByteArray.Encoding as B
import qualified Data.ByteString.Char8 as B8
import Crypto.Hash

type Hash = Digest SHA256

(...) = (.) . (.)

(.+.) :: (Num a, Integral a) => [a] -> [a] -> [a]
(.+.) = zipWith (+)

(.-.) :: (Num a, Integral a) => [a] -> [a] -> [a]
(.-.) = zipWith (-)

(.*.) :: (Num a, Integral a) => [a] -> [a] -> [a]
(.*.) = zipWith (*)

vectorInner :: (Num a, Integral a) => [a] -> [a] -> a
vectorInner = (sum ... (.*.))

ecHadamard :: Curve -> [Integer] -> [Point] -> [Point]
ecHadamard crv xs ys = zipWith (pointMul crv) xs ys 

ecInner :: Curve -> [Integer] -> [Point] -> Point
ecInner crv xs ps = foldl' (pointAdd crv) PointO $ ecHadamard crv xs ps

expVector :: Integer -> Integer -> [Integer]
expVector n y = (^) y <$> [0..(n-1)]

perturbH :: Curve -> Point -> Integer -> [Point]
perturbH crv p n = flip (pointMul crv) p <$> hindex
    where
        hindex = parseHexHash <$> (perturbPoint (ecc_g $ common_curve crv) <$> [1..(fromInteger n)])

perturbBase :: Curve -> Integer -> [Point]
perturbBase crv n = pointBaseMul crv <$> gIndex
    where
        gIndex = parseHexHash <$> (perturbPoint (ecc_g $ common_curve crv) <$> [1..(fromInteger n)])
        
perturbPoint :: Point -> Int -> Hash
perturbPoint PointO _ = hash $ ("" :: B8.ByteString)
perturbPoint (Point x y ) n = hash <$> B8.pack $ (show x <> show y <> show n)

parseHexHash :: Hash -> Integer
parseHexHash h = toInteger $ parser $ reverse str
    where
        str = show h
        parser []     = 0
        parser (h:hs) = digitToInt h + 16 * parser hs
        
pointToByte :: Point -> B8.ByteString
pointToByte PointO = "" :: B8.ByteString
pointToByte (Point x y) = B.convert hashedPoint
    where
        hashedPoint :: Hash = hash <$> B8.pack $ (show x <> show y)

-- hashToInt :: Hash -> Integer
-- hashToInt = (parseHex . show )