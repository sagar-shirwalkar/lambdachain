{-# LANGUAGE BangPatterns #-}

module Cryptography.Hash where

import qualified Crypto.Hash as H
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString as B

hashString :: String -> String
hashString s = 
  let bs = B8.pack s
      digest = H.hash bs :: H.Digest H.Blake2b_256
  in show digest

hashBytes :: B.ByteString -> String
hashBytes bs =
  let digest = H.hash bs :: H.Digest H.Blake2b_256
  in show digest

hash :: String -> String
hash = hashString

hashWithSalt :: B.ByteString -> B.ByteString -> String
hashWithSalt salt input =
  let combined = salt <> input
      digest = H.hash combined :: H.Digest H.Blake2b_256
  in show digest

defaultSalt :: B.ByteString
defaultSalt = B.replicate 16 0

secureHash :: String -> String
secureHash input = hashWithSalt defaultSalt (B8.pack input)

secureHashBytes :: B.ByteString -> String
secureHashBytes input = hashWithSalt defaultSalt input
