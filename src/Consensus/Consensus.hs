module Consensus.Consensus where

import Blockchain.Blockchain
import Block.Block
import Hash.Hash

-- Proof-of-Work consensus algorithm
data Consensus = ProofOfWork Int  -- Difficulty level
  deriving (Show, Eq)

-- Validate if a block satisfies proof-of-work requirements
validateProof :: Block -> Int -> Bool
validateProof block difficulty = 
  let target = replicate difficulty '0'
      hash = blockHash block
      calculatedHash = calculateBlockHash block
  in hash == calculatedHash && take difficulty hash == target

-- Adjust difficulty based on time taken to mine previous blocks
adjustDifficulty :: Blockchain -> Int
adjustDifficulty bc = 
  case chain bc of
    [] -> 4  -- Default difficulty
    [_] -> 4  -- Default difficulty for chains with only genesis block
    (block1:block2:_) -> 
      -- Simple adjustment: if time difference is greater than target, decrease difficulty
      -- In a real implementation, this would be more sophisticated
      let timeDiff = blockTimestamp block1 - blockTimestamp block2
          targetTime = 10  -- Target time in seconds
      in if timeDiff > targetTime 
           then max 1 (difficulty bc - 1)  -- Decrease difficulty, minimum 1
           else difficulty bc + 1            -- Increase difficulty

-- Select the longest valid chain as the authoritative chain
selectChain :: [Blockchain] -> Maybe Blockchain
selectChain [] = Nothing
selectChain chains = Just (longestChain chains)
  where
    longestChain = foldl1 (\bc1 bc2 -> if length (chain bc1) > length (chain bc2) then bc1 else bc2)

-- Verify that a node has done the required work
verifyNodeWork :: Block -> Int -> Bool
verifyNodeWork block requiredDifficulty = validateProof block requiredDifficulty

-- Calculate mining reward (simplified)
miningReward :: Int -> Double
miningReward blockHeight = 50.0 / (2.0 ^ fromIntegral (blockHeight `div` 210000))

-- Check if the blockchain satisfies consensus rules
validateConsensus :: Blockchain -> Bool
validateConsensus bc = 
  let chainBlocks = chain bc
  in case chainBlocks of
       [] -> True  -- Empty chain is valid
       [_] -> True  -- Single block (genesis) is valid
       _ -> all (\block -> validateProof block (difficulty bc)) chainBlocks

-- Create a new consensus mechanism with specified difficulty
newConsensus :: Int -> Consensus
newConsensus difficulty = ProofOfWork difficulty

-- Get the current difficulty from consensus
getDifficulty :: Consensus -> Int
getDifficulty (ProofOfWork diff) = diff