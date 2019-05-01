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
import Crypto.Number.ModArithmetic

type Hash = Digest SHA256

crv :: Curve
crv = getCurveByName SEC_p256k1

q :: Integer
q = ecc_n $ common_curve crv

g :: Point
g = ecc_g $ common_curve crv

(...) = (.) . (.)

(.+.) :: (Num a, Integral a) => [a] -> [a] -> [a]
(.+.) = zipWith (+)

(.-.) :: (Num a, Integral a) => [a] -> [a] -> [a]
(.-.) = zipWith (-)

(.*.) :: (Num a, Integral a) => [a] -> [a] -> [a]
(.*.) = zipWith (*)

vectorInner :: (Num a, Integral a) => [a] -> [a] -> a
vectorInner = (sum ... (.*.))

ecHadamard :: [Integer] -> [Point] -> [Point]
ecHadamard xs ys = zipWith (pointMul crv) xs ys 

ecInner :: [Integer] -> [Point] -> Point
ecInner xs ps = foldl' (pointAdd crv) PointO $ ecHadamard xs ps

vectorPow :: Integer -> Integer -> [Integer]
vectorPow y n= (\i -> if i == 0 && y == 0 then 0 else expSafe y i q) <$> [0..n-1]

perturbH :: Point -> Integer -> [Point]
perturbH p n = flip (pointMul crv) p <$> hindex
    where
        hindex = parseHexHash <$> (perturbPoint p <$> [1..(fromInteger n)])

perturbBase :: Integer -> [Point]
perturbBase n = pointBaseMul crv <$> gIndex
    where
        gIndex = parseHexHash <$> (perturbPoint g <$> [1..(fromInteger n)])
        
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