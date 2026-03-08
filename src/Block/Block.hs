{-# LANGUAGE DeriveGeneric #-}

module Block.Block where

import MerkleTree.MerkleTree
import Hash.Hash
import GHC.Generics(Generic)
import Data.Aeson

-- Define the block structure
data Block = Block
  { blockIndex :: Int
  , blockTimestamp :: Integer
  , blockTransactions :: [String]
  , blockPreviousHash :: String
  , blockNonce :: Int
  , blockHash :: String
  , blockMerkleTree :: MerkleTree
  } deriving (Show, Eq, Generic)

instance ToJSON Block
instance FromJSON Block
  
-- Function to construct a block
constructBlock :: Int -> Integer -> [String] -> String -> Int -> String -> Block
constructBlock index timestamp transactions prevHash nonce hashValue = 
  let 
    merkleTree = constructMerkleTree transactions
  in 
    Block 
      { blockIndex = index
      , blockTimestamp = timestamp
      , blockTransactions = transactions
      , blockPreviousHash = prevHash
      , blockNonce = nonce
      , blockHash = hashValue
      , blockMerkleTree = merkleTree
      }

-- Simplified constructor for easier block creation
newBlock :: [String] -> String -> Block
newBlock transactions prevHash = 
  Block
    { blockIndex = 0
    , blockTimestamp = 0
    , blockTransactions = transactions
    , blockPreviousHash = prevHash
    , blockNonce = 0
    , blockHash = ""
    , blockMerkleTree = constructMerkleTree transactions
    }

-- Calculate the hash of a block
calculateBlockHash :: Block -> String
calculateBlockHash block = 
  hashString $ show (blockIndex block) ++ 
                show (blockTimestamp block) ++ 
                show (blockTransactions block) ++ 
                blockPreviousHash block ++ 
                show (blockNonce block)
