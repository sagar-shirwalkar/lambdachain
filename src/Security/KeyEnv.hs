module Security.KeyEnv where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Base64 as B64
import System.Environment (lookupEnv)
import Crypto.PubKey.Ed25519
import Crypto.Error (CryptoFailable(..))

class Key a where
  getKey :: IO a

-- | Get a secret from environment, optionally Base64 decoded
getDecodedSecret :: String -> B.ByteString -> IO B.ByteString
getDecodedSecret envVar fallback = do
  mVal <- lookupEnv envVar
  case mVal of
    Just val -> do
      let bs = BC.pack val
      case B64.decode bs of
        Right decoded -> return decoded
        Left _ -> do
          putStrLn $ "Warning: Failed to Base64 decode " ++ envVar ++ ". Using raw value."
          return bs
    Nothing -> do
      putStrLn $ "Warning: Using fallback key for " ++ envVar ++ ". Set " ++ envVar ++ " in production!"
      return fallback

instance Key SecretKey where
  getKey = do
    let fallback = B.replicate 32 0
    keyBytes <- getDecodedSecret "ZKP_SIGNING_KEY" fallback
    let key = if B.length keyBytes < 32 
              then keyBytes <> B.replicate (32 - B.length keyBytes) 0
              else B.take 32 keyBytes
    case secretKey key of
      CryptoPassed sk -> return sk
      CryptoFailed err -> error $ "Failed to import Ed25519 SecretKey: " ++ show err

instance Key PublicKey where
  getKey = do
    sk <- getKey :: IO SecretKey
    return $! toPublic sk

getHashSalt :: IO B.ByteString
getHashSalt = do
  let fallback = B.replicate 16 0
  getDecodedSecret "HASH_SALT" fallback
