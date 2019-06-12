module EC_Mult (pippenger) where

import Constants
import Data.Bits
import qualified Data.Map as Map
import Crypto.PubKey.ECC.Types
import Crypto.PubKey.ECC.Prim

-------------------------------------------------------------
-- Better Elliptic Curve Multiplication using Pippenger's  --
-------------------------------------------------------------


nToRadix :: Integer -> Integer -> [Integer]
nToRadix i k
    | i `mod` k == 0 = 0 : nToRadix (i `div` k) k 
    | i < k = [i]
    | otherwise =  (i `mod` k ) : nToRadix (i `div` k) k 

radix2w :: Integer -> Int -> [Integer]
radix2w num w = signedDigit padded_reg_rep
    where
        reg_rep = nToRadix num radix
        padding = 256 - length reg_rep
        padded_reg_rep = reg_rep ++ (replicate padding 0 )
        radix = 2^w 
        signedDigit :: [Integer] -> [Integer]
        signedDigit [] = []
        signedDigit [d] = [d]
        signedDigit (d:ds:dss) = d': signedDigit (ds':dss)
            where
                carry = shiftR (d + (radix `div` 2)) w
                d' = d - (shiftL carry w)
                ds' = ds + carry

pippenger :: [(Integer,Point)] -> Point
pippenger ips
    | Prelude.length ips < 500 = runPipp ips 6
    | Prelude.length ips < 800 = runPipp ips 7
    | otherwise = runPipp ips 8
    where
        runPipp :: [(Integer,Point)] -> Int -> Point
        runPipp pairs w = agg_buckets_sum
            where
                max_digit = shiftL 1 w
                digits_count = radix_size_hint w
                buckets_count = max_digit `div` 2
                indexedIDBuckets = zip [0..buckets_count-1] $ repeat PointO
                bucketIntPair = Prelude.replicate digits_count $ Prelude.foldr (\x acc -> Map.insert (fst x) (snd x) acc) Map.empty $ indexedIDBuckets
                scalars = fst <$> pairs
                point = snd <$> pairs
                w_radixScalars = (\i -> radix2w i w) <$> scalars
                radixScalarPoint = zip w_radixScalars point
                final_buckets = foldl (\acc x -> sortIntoBucket (digits_count-1) x acc) bucketIntPair radixScalarPoint
                list_buckets = Map.toList <$> final_buckets
                pointBucketList = (snd <$>) <$> list_buckets
                bucket_sum = Prelude.foldr1 (pointAdd crv) <$> Prelude.scanl1 (pointAdd crv) <$> Prelude.reverse <$> pointBucketList
                agg_buckets_sum = Prelude.foldl1 (\acc pt -> pointAdd crv (doubling w acc) pt) bucket_sum
                
                sortIntoBucket :: Int ->([Integer],Point) -> [Map.Map Integer Point] ->  [Map.Map Integer Point]
                sortIntoBucket (-1) _ map = map 
                sortIntoBucket n (digit,pt) (map:mapps)
                    | digit !! n > 0 = let b = (digit !! n) -1 in (Map.adjust (pointAdd crv pt) b map): sortIntoBucket (n-1) (digit,pt) mapps
                    | otherwise = let b = ((-1)*(digit !! n)) -1 in ( Map.adjust (pointAdd crv (pointNegate crv pt)) b map) : sortIntoBucket (n-1) (digit,pt) mapps 


radix_size_hint :: Int -> Int
radix_size_hint w = (256 + w -1) `div` w

doubling :: Int -> Point -> Point
doubling 0 p = p
doubling n p = doubling (n-1) $ pointDouble crv p 