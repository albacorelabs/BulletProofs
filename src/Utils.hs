{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Utils where

import Data.Char
import Crypto.PubKey.ECC.Prim
import Crypto.PubKey.ECC.Types
import Data.List (foldl')
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Encoding as BA
import qualified Data.ByteString.Char8 as B8
import Crypto.Hash
import Crypto.Number.ModArithmetic
import qualified Data.ByteString as B
import Data.Word(Word8)
import Crypto.Number.Serialize
import qualified Data.Serialize as S
import Constants
import EC_Mult


instance S.Serialize Point where
    put p = 
        S.putByteString $ compressPoint p
    get = do
        p' <- S.getByteString 33
        return $ decompressPoint crv p'

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
ecInner xs ps = pippenger $ zip ((\x -> x `mod` q) <$> xs) ps

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
        parser (h:hs) = toInteger (digitToInt h) + 16 * parser hs
        
pointToByte :: Point -> B8.ByteString
pointToByte PointO = "" :: B8.ByteString
pointToByte (Point x y) = BA.convert hashedPoint
    where
        hashedPoint :: Hash = hash <$> B8.pack $ (show x <> show y)

-- Based on SECP_256k1 Bitcoin Compression --
compressPoint :: Point -> B.ByteString
compressPoint PointO = error "O point cannot be compressed"
compressPoint (Point x y) 
    | y `mod` 2 == 0 = B.cons (2 :: Word8) $ i2osp x
    | otherwise      = B.cons (3 :: Word8) $ i2osp x


decompressPoint :: Curve -> B.ByteString -> Point
decompressPoint (CurveF2m _) _ = error "Curve must be prime of type Fp"
decompressPoint (CurveFP  (CurvePrime p _)) bs = do
    let parityBit = BA.convertToBase BA.Base16 $ B.take 1 bs :: B.ByteString
        xCoord = os2ip $ (B.drop 1 bs :: B.ByteString)
        root = cipolla_sqrt p $ (xCoord^3 + 7) `mod` p
    if (parityBit == "02") then
        if (root `mod` 2 == 0 ) then
            Point xCoord root
        else
            Point xCoord $ (root * (-1)) `mod` p
    else
        if (root `mod` 2 /= 0 ) then
            Point xCoord root
        else
            Point xCoord $ (root * (-1)) `mod` p
    where
        cipolla_sqrt :: Integer -> Integer -> Integer
        cipolla_sqrt p n 
            | checkCongruence (expFast n ((p-1) `div` 2) p) 1 p = collapseMul
            | otherwise = error "Solution to y^2 is not a square"
            where
                a = find_valid_a n p 0
                omegaSquared = (a ^2 -n) `mod` p
                power = ((p+1) `div` 2) `mod` p
                (collapseMul,_) = fold_powers power omegaSquared p (1,0) (a,1)
        
                fold_powers :: Integer -> Integer -> Integer -> (Integer,Integer) -> (Integer,Integer) -> (Integer,Integer)
                fold_powers 0 _ _ x _ = x
                fold_powers n omegaSquared p r s
                    | n `mod` 2 == 1 = fold_powers (n `div` 2) omegaSquared p (cipolla_mul omegaSquared p r s) (cipolla_mul omegaSquared p s s)
                    | otherwise = fold_powers (n `div` 2) omegaSquared p r $ cipolla_mul omegaSquared p s s
        
                find_valid_a :: Integer -> Integer -> Integer -> Integer
                find_valid_a n p a
                    | checkCongruence base (-1) p = a
                    | otherwise = find_valid_a n p (a+1)
                    where
                        base = expFast (a^2 - n) ((p-1) `div` 2) p
        
                cipolla_mul :: Integer -> Integer -> (Integer,Integer) -> (Integer,Integer) -> (Integer,Integer)
                cipolla_mul omegaSquared p (a,b) (c,d) = (omega_sum ,i_sum)
                    where
                        omega_sum = (a * c + b * d * omegaSquared) `mod` p
                        i_sum = (a * d + c * b ) `mod` p

                checkCongruence:: Integer -> Integer -> Integer -> Bool
                checkCongruence a_1 b_1 modm
                    | (a_1-b_1) `mod` modm == 0 = True
                    | otherwise = False
                        