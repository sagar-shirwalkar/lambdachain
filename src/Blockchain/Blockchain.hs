{-# LANGUAGE DeriveGeneric #-}

module Blockchain.Blockchain where

import GHC.Generics (Generic)
import Block.Block
import Hash.Hash
import MerkleTree.MerkleTree
import Data.List (find, sortBy)
import qualified Data.Map as Map
import Data.Time.Clock
import Data.Ord (comparing)
import Data.Aeson

-- Define the blockchain structure
data Blockchain = Blockchain
  { chain :: [Block]
  , difficulty :: Int
  } deriving (Show, Eq, Generic)

instance ToJSON Blockchain
instance FromJSON Blockchain  

-- Create a new blockchain with genesis block
newBlockchain :: Int -> Blockchain
newBlockchain d = Blockchain { chain = [genesisBlock], difficulty = d }
  where
    genesisBlock = Block
      { blockIndex = 0
      , blockTimestamp = 0
      , blockTransactions = ["Genesis Block"]
      , blockPreviousHash = "0"
      , blockNonce = 0
      , blockHash = hashString "Genesis"
      , blockMerkleTree = constructMerkleTree ["Genesis Block"]
      }

-- Validate a block
validateBlock :: Block -> Block -> Bool
validateBlock newBlock previousBlock = 
  blockIndex newBlock == blockIndex previousBlock + 1 &&
  blockPreviousHash newBlock == blockHash previousBlock

-- Add a new block to the chain
addBlock :: Blockchain -> [String] -> Blockchain
addBlock bc transactions =
  let prevBlock = head (chain bc)
      newIndex = blockIndex prevBlock + 1
      timestamp = 0  -- In a real implementation, use current time
      minedBlock = mineBlock (Block
        { blockIndex = newIndex
        , blockTimestamp = timestamp
        , blockTransactions = transactions
        , blockPreviousHash = blockHash prevBlock
        , blockNonce = 0
        , blockHash = ""
        , blockMerkleTree = constructMerkleTree transactions
        }) (difficulty bc)
  in bc { chain = minedBlock : chain bc }

-- Mine a block until it meets difficulty requirement
mineBlock :: Block -> Int -> Block
mineBlock block diff =
  let target = replicate diff '0'
      minedBlock = mineHelper block target 0
  in minedBlock

-- Helper function to mine a block
mineHelper :: Block -> String -> Int -> Block
mineHelper block target nonce =
  let blockWithNonce = block { blockNonce = nonce }
      hash = calculateBlockHash blockWithNonce
  in if take (length target) hash == target
       then blockWithNonce { blockHash = hash }
       else mineHelper block target (nonce + 1)

-- Validate the entire blockchain
validateChain :: Blockchain -> Bool
validateChain bc = validateChainHelper (chain bc)
  where
    validateChainHelper [] = True
    validateChainHelper [_] = True
    validateChainHelper (x:y:xs) = validateBlock x y && validateChainHelper (y:xs)

-- Get the length of the blockchain
getChainLength :: Blockchain -> Int
getChainLength bc = length (chain bc)

-- Get the latest block
getLatestBlock :: Blockchain -> Maybe Block
getLatestBlock bc = 
  case chain bc of
    [] -> Nothing
    (x:_) -> Just x

-- Replace the chain if the new chain is longer and valid
replaceChain :: Blockchain -> [Block] -> Blockchain
replaceChain bc newChain = 
  if length newChain > length (chain bc) && validateChain (Blockchain newChain (difficulty bc))
    then bc { chain = newChain }
    else bc
