{-# LANGUAGE DeriveGeneric #-}

module MerkleTree.MerkleTree where

import GHC.Generics (Generic)
import Data.Aeson
import Hash.Hash (hashString)

-- Merkle Trees
data MerkleTree = Leaf String | Node String MerkleTree MerkleTree
  deriving (Show, Eq, Generic)
  
instance ToJSON MerkleTree
instance FromJSON MerkleTree

-- Function to construct a Merkle tree from a list of transactions
constructMerkleTree :: [String] -> MerkleTree
constructMerkleTree [] = Leaf ""
constructMerkleTree [tx] = Leaf (hashString tx)
constructMerkleTree transactions = 
  let 
    mid = length transactions `div` 2
    left = constructMerkleTree (take mid transactions)
    right = constructMerkleTree (drop mid transactions)
    leftHash = hashTree left
    rightHash = hashTree right
  in 
    Node (leftHash ++ rightHash) left right

-- Helper function to get the hash of a tree node
hashTree :: MerkleTree -> String
hashTree tree = 
  case tree of
    Leaf h -> h
    Node h _ _ -> h

-- Function to verify a Merkle tree
verifyMerkleTree :: MerkleTree -> Bool
verifyMerkleTree tree = 
  case tree of 
    Leaf h -> not (null h)
    Node h left right -> 
      verifyMerkleTree left && 
      verifyMerkleTree right &&
      h == (hashTree left ++ hashTree right)

-- Function to get the root hash of a Merkle tree
getMerkleRoot :: MerkleTree -> String
getMerkleRoot tree = hashTree tree