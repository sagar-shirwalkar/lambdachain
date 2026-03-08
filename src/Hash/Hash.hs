module Hash.Hash where

import qualified Crypto.Hash as H
import qualified Data.ByteString.Char8 as B8

-- Calculate the BLAKE2b hash of a string
hashString :: String -> String
hashString s = 
  let bs = B8.pack s
      digest = H.hash bs :: H.Digest H.Blake2b_256
  in show digest

-- Calculate hash of a Merkle tree (used in other modules)
hash :: String -> String
hash = hashString