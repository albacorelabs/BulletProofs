module Constants where
    
import Crypto.PubKey.ECC.Types
import qualified Data.Serialize as S
import Crypto.Hash 

--------------------------------------------------------------
-- Constants used through this Bulletproofs Implmementation --
--------------------------------------------------------------

type Hash = Digest SHA256

crv :: Curve
crv = getCurveByName SEC_p256k1

q :: Integer
q = ecc_n $ common_curve crv

g :: Point
g = ecc_g $ common_curve crv
