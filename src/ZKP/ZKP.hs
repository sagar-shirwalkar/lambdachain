{-# LANGUAGE DeriveGeneric #-}

module ZKP.ZKP where

import Hash.Hash
import Data.Aeson
import GHC.Generics
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Base64 as B64
import Crypto.PubKey.Ed25519
import Crypto.Error
import Data.ByteArray (convert)

data ZKP = ZKP 
  { zkpStatement :: String
  , zkpSignature :: String
  } deriving (Show, Eq, Generic)

instance ToJSON ZKP
instance FromJSON ZKP

createZKP :: String -> String -> ZKP
createZKP = ZKP

verifyZKP :: ZKP -> Bool
verifyZKP zkp = 
  let statement = zkpStatement zkp
      proof = zkpSignature zkp
  in not (null statement) && not (null proof)

generateZKProof :: String -> String -> ZKP
generateZKProof transaction sKey = 
  let statement = hash transaction
      proof = hash (transaction ++ sKey)
  in ZKP statement proof

signatureToBytes :: Signature -> B.ByteString
signatureToBytes = convert

createEd25519ZKP :: B.ByteString -> SecretKey -> ZKP
createEd25519ZKP statement sKey = 
  let pk = toPublic sKey
      sig = sign sKey pk statement
  in ZKP 
    { zkpStatement = bsToString (B64.encode statement)
    , zkpSignature = bsToString (B64.encode (signatureToBytes sig))
    }

verifyEd25519ZKP :: ZKP -> PublicKey -> Bool
verifyEd25519ZKP zkp pubKey = 
  let mStatement = B64.decode (BC.pack (zkpStatement zkp))
      mSignature = B64.decode (BC.pack (zkpSignature zkp))
  in case (mStatement, mSignature) of
    (Right statement, Right sigBS) -> 
      case signature sigBS of
        CryptoFailed _ -> False
        CryptoPassed sig -> verify pubKey statement sig
    _ -> False

generateEd25519ZKProof :: B.ByteString -> SecretKey -> ZKP
generateEd25519ZKProof transaction sKey = 
  let statementHash = hashBytes transaction
      statementBS = BC.pack statementHash
  in createEd25519ZKP statementBS sKey

getPublicKey :: SecretKey -> PublicKey
getPublicKey = toPublic

bsToString :: B.ByteString -> String
bsToString = BC.unpack
