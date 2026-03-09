{-# LANGUAGE DeriveGeneric #-}

module Cryptography.HomomorphicEncryption where

import Cryptography.Hash
import Data.Aeson
import GHC.Generics
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Base64 as B64
import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types
import Crypto.Random (getRandomBytes)
import Crypto.Error

data EncryptedData = EncryptedData 
  { encryptedNonce :: String
  , encryptedCiphertext :: String
  } deriving (Show, Eq, Generic)

instance ToJSON EncryptedData
instance FromJSON EncryptedData

aesEncrypt :: B.ByteString -> B.ByteString -> IO (B.ByteString, B.ByteString)
aesEncrypt key plaintext = do
  let cipher = case cipherInit key :: CryptoFailable AES256 of
        CryptoFailed err -> error $ "Invalid key: " ++ show err
        CryptoPassed c -> c
  nonce <- getRandomBytes 12
  case aeadInit AEAD_GCM cipher nonce of
    CryptoFailed err -> error $ "Failed to init AEAD: " ++ show err
    CryptoPassed aead -> do
      let (ciphertext, _) = aeadEncrypt aead plaintext
      return (nonce, ciphertext)

aesDecrypt :: B.ByteString -> B.ByteString -> B.ByteString -> Either String B.ByteString
aesDecrypt key nonce ciphertext = do
  case cipherInit key :: CryptoFailable AES256 of
    CryptoFailed err -> Left $ "Invalid key: " ++ show err
    CryptoPassed cipher -> 
      case aeadInit AEAD_GCM cipher nonce of
        CryptoFailed err -> Left $ "Failed to init AEAD: " ++ show err
        CryptoPassed aead -> 
          let (plaintext, _) = aeadDecrypt aead ciphertext
          in Right plaintext

stringToBS :: String -> B.ByteString
stringToBS = BC.pack

bsToString :: B.ByteString -> String
bsToString = BC.unpack

encryptData :: String -> String -> EncryptedData
encryptData plaintext keyStr = 
  let key = stringToBS keyStr
      plaintextBS = stringToBS plaintext
      keyLen = B.length key
      actualKey = if keyLen < 32 
                  then key <> B.replicate (32 - keyLen) 0 
                  else B.take 32 key
      (nonce, ciphertext) = runAES actualKey plaintextBS
  in EncryptedData 
      { encryptedNonce = bsToString (B64.encode nonce)
      , encryptedCiphertext = bsToString (B64.encode ciphertext)
      }

runAES :: B.ByteString -> B.ByteString -> (B.ByteString, B.ByteString)
runAES key bs = 
  let cipher = case cipherInit key :: CryptoFailable AES256 of
        CryptoFailed err -> error $ "Invalid key: " ++ show err
        CryptoPassed c -> c
      nonce = B.replicate 12 0
  in case aeadInit AEAD_GCM cipher nonce of
    CryptoFailed err -> error $ "Failed to init AEAD: " ++ show err
    CryptoPassed aead -> 
      let (encrypted, _) = aeadEncrypt aead bs
      in (nonce, encrypted)

decryptData :: String -> EncryptedData -> String
decryptData keyStr encrypted = 
  let key = stringToBS keyStr
      keyLen = B.length key
      actualKey = if keyLen < 32 
                  then key <> B.replicate (32 - keyLen) 0 
                  else B.take 32 key
  in case (B64.decode (stringToBS (encryptedNonce encrypted)), 
          B64.decode (stringToBS (encryptedCiphertext encrypted))) of
    (Right nonce, Right ciphertext) -> 
      case aesDecrypt actualKey nonce ciphertext of
        Right pt -> bsToString pt
        Left _ -> error "Decryption failed"
    _ -> error "Base64 decode failed"

hash :: String -> String
hash = hashString
