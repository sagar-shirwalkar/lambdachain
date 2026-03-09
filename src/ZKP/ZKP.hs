{-# LANGUAGE DeriveGeneric #-}

module ZKP.ZKP
  ( ZKParams(..)
  , ZKP(..)
  , defaultParams
  , getPublicKey
  , generateZKProof
  , generateZKProofIO
  , verifyZKP
  , verifyZKPWithKey
  , toHex
  , fromHex
  , bsToString
  , powerMod
  ) where

import GHC.Generics              (Generic)
import Data.Aeson                (ToJSON, FromJSON)
import qualified Crypto.Hash as H
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Crypto.Number.ModArithmetic (expSafe)
import Crypto.Number.Serialize     (os2ip)
import Crypto.Number.Generate      (generateMax)
import Data.ByteArray              (convert)
import Numeric                     (showHex, readHex)

-- Schnorr prime-order group parameters.
data ZKParams = ZKParams
  { paramP :: !Integer   -- Safe prime modulus
  , paramQ :: !Integer   -- Prime order of subgroup, q | (p−1)
  , paramG :: !Integer   -- Generator of the order-q subgroup of Z*_p
  } deriving (Show, Eq, Generic)

instance ToJSON ZKParams
instance FromJSON ZKParams

-- Non-Interactive Zero-Knowledge Proof - Schnorr sigma-protocol (Fiat-Shamir).
-- Completeness: g^s · y^c  =  g^(r−cx) · g^(xc)  =  g^r  =  t
-- Soundness: c is unpredictable before t is committed.
--   * Zero-knowledge – proof reveals nothing about x:
--       1. simulator picks random (s,c), sets t = g^s·y^c,
--       2. programs H(…) = c.  Transcript is indistinguishable.
data ZKP = ZKP
  { zkpStatement  :: !String   -- Public key    y  (hex)
  , zkpCommitment :: !String   -- Commitment    t  (hex)
  , zkpChallenge  :: !String   -- Challenge     c  (hex)
  , zkpResponse   :: !String   -- Response      s  (hex)
  } deriving (Show, Eq, Generic)

instance ToJSON ZKP
instance FromJSON ZKP

-- Group parameters  (RFC 3526 2048-bit MODP safe prime)

-- Default parameters.
--   p = RFC 3526 2048-bit safe prime
--   q = (p − 1) / 2 (also prime)
--   g = 4  (2^2; guaranteed order q because 2 generates Z*_p and squaring drops into the order-q QR subgroup)
defaultParams :: ZKParams
defaultParams = ZKParams { paramP = p, paramQ = q, paramG = 4 }
  where
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    q = (p - 1) `div` 2

-- Core protocol

-- Derive the public key from a secret key (@y  =  g^x  mod p@)
getPublicKey :: ZKParams -> Integer -> Integer
getPublicKey params x = expSafe (paramG params) x (paramP params)

-- Fiat-Shamir challenge: deterministic, collision-resistant.
--   @c  =  SHA-256(len(g) : g || len(y) : y || len(t) : t || ctx)  mod q@
computeChallenge :: ZKParams -> Integer -> Integer -> B.ByteString -> Integer
computeChallenge params y t ctx =
  let input = B.concat
        [ encodeDL (paramG params)
        , encodeDL y
        , encodeDL t
        , ctx
        ]
      digest = H.hash input :: H.Digest H.SHA256
  in os2ip (convert digest :: B.ByteString) `mod` paramQ params
  where
    -- Domain-separated, length-prefixed encoding to prevent ambiguous concatenation
    encodeDL :: Integer -> B.ByteString
    encodeDL n =
      let hex = BC.pack (showHex n "")
          pre = BC.pack (show (B.length hex) ++ ":")
      in pre <> hex

-- Generate a ZKP  (pure; caller supplies the nonce).
--   WARNING: the nonce @r@ /must/ be cryptographically random
--   and /must never be reused/.  Reuse leaks the secret key
--   (same failure mode as ECDSA nonce reuse).
generateZKProof :: ZKParams
                -> Integer        -- Secret  x  ∈ [1, q−1]
                -> Integer        -- Nonce   r  ∈ [1, q−1]  (random, unique!)
                -> B.ByteString   -- Context (e.g. transaction hash)
                -> ZKP
generateZKProof params x r ctx
  | r <= 0 || r >= paramQ params =
      error "ZKP: nonce r must be in [1, q-1]"
  | x <= 0 || x >= paramQ params =
      error "ZKP: secret x must be in [1, q-1]"
  | otherwise =
      let p = paramP params
          q = paramQ params
          g = paramG params
          y = expSafe g x p                        -- public key
          t = expSafe g r p                        -- commitment
          c = computeChallenge params y t ctx       -- Fiat-Shamir challenge
          s = (r - c * x) `mod` q                  -- response
      in ZKP
        { zkpStatement  = toHex y
        , zkpCommitment = toHex t
        , zkpChallenge  = toHex c
        , zkpResponse   = toHex s
        }

-- Generate a ZKP with a cryptographically secure random nonce.
generateZKProofIO :: ZKParams -> Integer -> B.ByteString -> IO ZKP
generateZKProofIO params x ctx = do
  r <- randomInRange 1 (paramQ params - 1)
  return $ generateZKProof params x r ctx

-- Verify a Zero-Knowledge Proof.
--
--   Checks (all must hold):
--
--   1. All values in valid ranges
--   2. y, t in order-q subgroup  (prevents small-subgroup attacks)
--   3. Challenge matches  c == H(g || y || t || ctx)
--   4. Proof equation     g^s · y^c ≡ t  (mod p)
verifyZKP :: ZKParams -> ZKP -> B.ByteString -> Bool
verifyZKP params zkp ctx =
  let p = paramP params
      q = paramQ params
      g = paramG params
      y = fromHex (zkpStatement  zkp)
      t = fromHex (zkpCommitment zkp)
      c = fromHex (zkpChallenge  zkp)
      s = fromHex (zkpResponse   zkp)
      expectedC = computeChallenge params y t ctx
      lhs       = (expSafe g s p * expSafe y c p) `mod` p
  in and
       [ -- Range checks
         y > 1, y < p
       , t > 0, t < p
       , c >= 0, c < q
       , s >= 0, s < q
         -- Subgroup membership (order-q)
       , expSafe y q p == 1
       , expSafe t q p == 1
         -- Challenge consistency  (Fiat-Shamir)
       , c == expectedC
         -- Core proof equation
       , lhs == t
       ]

-- Verify a ZKP against a /known/ public key (from the blockchain ledger).
verifyZKPWithKey :: ZKParams -> ZKP -> Integer -> B.ByteString -> Bool
verifyZKPWithKey params zkp expectedPK ctx =
  fromHex (zkpStatement zkp) == expectedPK
  && verifyZKP params zkp ctx

-- -- Blockchain convenience API  (original function names)

-- -- Construct a ZKP value from its four components.
-- createZKP :: String -> String -> String -> String -> ZKP
-- createZKP = ZKP

-- -- Prove transaction authorisation: "I know the secret key for this address."
-- generateEd25519ZKProof :: B.ByteString -> Integer -> IO ZKP
-- generateEd25519ZKProof txData secret =
--   generateZKProofIO defaultParams secret txData

-- -- Verify transaction authorisation proof.
-- verifyEd25519ZKP :: ZKP -> B.ByteString -> Bool
-- verifyEd25519ZKP zkp txData = verifyZKP defaultParams zkp txData

-- Helpers

toHex :: Integer -> String
toHex n = showHex n ""

fromHex :: String -> Integer
fromHex s = case readHex s of
  ((n, ""):_) -> n
  _           -> -1          -- fails every range check in verifyZKP

randomInRange :: Integer -> Integer -> IO Integer
randomInRange lo hi = do
  r <- generateMax (hi - lo + 1)
  return (r + lo)

bsToString :: B.ByteString -> String
bsToString = BC.unpack

-- Modular exponentiation (re-export for testing)
powerMod :: Integer -> Integer -> Integer -> Integer
powerMod = expSafe
