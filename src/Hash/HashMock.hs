module Hash.Hash where

-- Mock hash function for testing without external dependencies
hashString :: String -> String
hashString s = "hash_" ++ show (length s) ++ "_" ++ take 8 (show (sum (map fromEnum s)))

-- Calculate hash of a Merkle tree (used in other modules)
hash :: String -> String
hash = hashString