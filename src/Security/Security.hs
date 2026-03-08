module Security.Security where

import ZKP.ZKP
import Security.HomomorphicEncryption
import Security.KeyEnv
import qualified Data.ByteString.Char8 as BC
import Crypto.PubKey.Ed25519

createPrivateTransaction :: String -> IO ZKP
createPrivateTransaction transaction = do
  txnSecretKey <- getKey :: IO SecretKey
  let txBytes = BC.pack transaction
  return $ generateEd25519ZKProof txBytes txnSecretKey

verifyPrivateTransaction :: ZKP -> IO Bool
verifyPrivateTransaction zkp = do
  txnPublicKey <- getKey :: IO PublicKey
  return $ verifyEd25519ZKP zkp txnPublicKey

createEncryptedTransaction :: String -> String -> IO (ZKP, EncryptedData)
createEncryptedTransaction transaction key = do
  zkp <- createPrivateTransaction transaction
  let encrypted = encryptData transaction key
  return (zkp, encrypted)

verifyAndDecrypt :: ZKP -> String -> EncryptedData -> IO (Maybe String)
verifyAndDecrypt zkp key encryptedData = do
  valid <- verifyPrivateTransaction zkp
  if valid
    then return $ Just (decryptData key encryptedData)
    else return Nothing
