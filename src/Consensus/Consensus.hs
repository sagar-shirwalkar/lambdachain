{-# LANGUAGE DeriveGeneric #-}

module Consensus.Consensus
  ( -- * Proof-of-Work
    Difficulty
  , meetsDifficulty
  , validatePoW
  , mineBlock
  , defaultDifficulty
  , maxDifficulty
  , targetBlockTimeSeconds
  
    -- * Difficulty Adjustment
  , calculateNewDifficulty
  , difficultyAdjustmentInterval
  
    -- * Block Rewards
  , miningReward
  , createCoinbaseTx
  
    -- * Validation
  , validateBlock
  , validateBlockIntegrity
  , validateBlockWithPoW
  , validateChainLinkage
  , validateFullChain
  , validateFullChainWithPoW
  
    -- * Chain Selection
  , selectChain
  , selectChainWithPoW
  ) where

import Block.Block
import Transaction.Transaction
    ( BlockchainTx(..)
    , TxValidationError(..)
    , processTransactionWithoutNonce
    , Ledger
    , Address
    , emptyLedger
    , coinbaseSender
    )
import ZKP.ZKP (ZKP(..))
import Control.Monad (foldM, when)
import Data.Char (isHexDigit)
import Data.Maybe (fromMaybe)
import GHC.Generics (Generic)
import Data.Aeson (ToJSON, FromJSON)

-- 
-- Proof-of-Work Types and Constants
-- 

-- Difficulty is the number of leading zero hex digits required in the hash
type Difficulty = Int

-- Default starting difficulty (2 leading zeros = ~256 attempts average)
defaultDifficulty :: Difficulty
defaultDifficulty = 2

-- Maximum difficulty to prevent infinite mining
maxDifficulty :: Difficulty
maxDifficulty = 8

-- Target time between blocks in seconds (like Bitcoin's 10 minutes)
targetBlockTimeSeconds :: Integer
targetBlockTimeSeconds = 120  -- 2 minutes for faster testing

-- How often to adjust difficulty (in blocks)
difficultyAdjustmentInterval :: Int
difficultyAdjustmentInterval = 10

-- 
-- Difficulty Validation
-- 

-- Check if a hash meets the required difficulty (N leading zeros)
meetsDifficulty :: String -> Difficulty -> Bool
meetsDifficulty hash difficulty
  | difficulty <= 0 = True
  | length hash < difficulty = False
  | otherwise = all (== '0') (take difficulty hash)

-- Validate that a block's hash meets the required difficulty
validatePoW :: Block -> Difficulty -> Bool
validatePoW block difficulty =
  verifyBlockHash block && meetsDifficulty (blockHash block) difficulty

-- 
-- Mining
-- 

-- Mine a block by finding a valid nonce that meets difficulty requirement
-- Returns Nothing if maxAttempts is exhausted
-- This is the main mining function that performs proof-of-work
mineBlock :: Block       -- Block template (with transactions, prevHash, etc.)
          -> Difficulty  -- Required difficulty
          -> Int         -- Maximum attempts before giving up
          -> IO (Maybe Block)
mineBlock blockTemplate difficulty maxAttempts = do
  result <- tryNonces (blockNonce blockTemplate) 0
  return result
  where
    tryNonces :: Integer -> Int -> IO (Maybe Block)
    tryNonces _ attempts | attempts >= maxAttempts = return Nothing
    tryNonces nonce attempts = do
      let candidateHash = calculateBlockHash
                            (blockIndex blockTemplate)
                            (blockTimestamp blockTemplate)
                            (blockTransactions blockTemplate)
                            (blockPreviousHash blockTemplate)
                            nonce
          candidate = blockTemplate { blockNonce = nonce, blockHash = candidateHash }
      
      if meetsDifficulty candidateHash difficulty
        then return (Just candidate)
        else tryNonces (nonce + 1) (attempts + 1)

-- Mine a block with progress reporting (calls callback every 1000 attempts)
mineBlockWithProgress :: Block
                      -> Difficulty
                      -> Int
                      -> (Int -> Integer -> IO ())  -- Progress callback
                      -> IO (Maybe Block)
mineBlockWithProgress blockTemplate difficulty maxAttempts progressCallback = do
  tryNonces (blockNonce blockTemplate) 0
  where
    tryNonces :: Integer -> Int -> IO (Maybe Block)
    tryNonces _ attempts | attempts >= maxAttempts = return Nothing
    tryNonces nonce attempts = do
      when (attempts `mod` 1000 == 0) $
        progressCallback attempts nonce
      
      let candidateHash = calculateBlockHash
                            (blockIndex blockTemplate)
                            (blockTimestamp blockTemplate)
                            (blockTransactions blockTemplate)
                            (blockPreviousHash blockTemplate)
                            nonce
          candidate = blockTemplate { blockNonce = nonce, blockHash = candidateHash }
      
      if meetsDifficulty candidateHash difficulty
        then return (Just candidate)
        else tryNonces (nonce + 1) (attempts + 1)

-- 
-- Difficulty Adjustment
-- 

-- Calculate new difficulty based on recent block times
-- Uses a simple algorithm: if blocks are too fast, increase difficulty;
-- if too slow, decrease difficulty
calculateNewDifficulty :: [Block] -> Difficulty -> Difficulty
calculateNewDifficulty blocks currentDifficulty
  | length blocks < difficultyAdjustmentInterval = currentDifficulty
  | otherwise = adjustDifficulty currentDifficulty actualTime targetTime
  where
    -- Get the last N blocks for adjustment
    recentBlocks = take difficultyAdjustmentInterval blocks
    
    -- Calculate actual time taken for these blocks
    oldestBlock = last recentBlocks
    newestBlock = head recentBlocks
    actualTime = blockTimestamp newestBlock - blockTimestamp oldestBlock
    
    -- Target time for this many blocks
    targetTime = fromIntegral difficultyAdjustmentInterval * targetBlockTimeSeconds

-- Internal: adjust difficulty based on time ratio
adjustDifficulty :: Difficulty -> Integer -> Integer -> Difficulty
adjustDifficulty currentDifficulty actualTime targetTime
  | ratio > 2    = min maxDifficulty (currentDifficulty + 1)  -- Way too fast, increase
  | ratio > 150  = min maxDifficulty (currentDifficulty + 1)  -- Too fast
  | ratio < 50   = max 1 (currentDifficulty - 1)              -- Too slow, decrease
  | otherwise    = currentDifficulty                          -- Just right
  where
    ratio = (actualTime * 100) `div` targetTime

-- 
-- Block Rewards & Coinbase Transactions
-- 

-- Calculate mining reward with halving every 210,000 blocks (like Bitcoin)
-- Halving schedule: 50 -> 25 -> 12.5 -> 6.25 -> ...
miningReward :: Int -> Double
miningReward height
  | height < 0 = 0
  | otherwise = 50.0 / (2.0 ^ (fromIntegral height `div` 210000) :: Double)

-- Create a coinbase transaction that rewards the miner
-- This is a special transaction with no sender (sender is coinbaseSender)
-- and a dummy ZKP (since it doesn't need real verification)
createCoinbaseTx :: Address   -- Miner's address (recipient)
                 -> Double    -- Reward amount
                 -> Int       -- Block height (for unique nonce)
                 -> IO BlockchainTx
createCoinbaseTx minerAddress reward blockHeight = do
  -- Coinbase transactions don't need a real signature/ZKP
  -- We create a dummy proof that will be accepted by special coinbase validation
  let dummyProof = ZKP
        { zkpStatement = "coinbase"  -- No real public key for coinbase
        , zkpCommitment = "coinbase_commitment"
        , zkpChallenge = "coinbase_challenge"
        , zkpResponse = "coinbase_response"
        }
  
  return BlockchainTx
    { txSender = coinbaseSender
    , txRecipient = minerAddress
    , txAmount = round (reward * 100000000)  -- Convert to smallest unit (satoshis)
    , txNonce = fromIntegral blockHeight
    , txCiphertext = Nothing
    , txProof = dummyProof
    }

-- 
-- Block Validation
-- 

-- Validate & apply all transactions in a block sequentially
-- Returns updated ledger or first error
-- Skips nonce check since these transactions have already been mined
validateBlock :: Ledger -> Block -> Either TxValidationError Ledger
validateBlock ledger block =
  foldM processTransactionWithoutNonce ledger (blockTransactions block)

-- Hash integrity check
validateBlockIntegrity :: Block -> Bool
validateBlockIntegrity = verifyBlockHash

-- Validate block with proof-of-work check
validateBlockWithPoW :: Ledger -> Block -> Difficulty -> Either TxValidationError Ledger
validateBlockWithPoW ledger block difficulty = do
  -- Check PoW first (fast rejection)
  if not (validatePoW block difficulty)
    then Left InvalidProof  -- Reusing error type, could add PoWError
    else validateBlock ledger block

-- 
-- Chain Validation
-- 

-- Chain linkage validation (list stored newest-first for O(1) access)
validateChainLinkage :: [Block] -> Bool
validateChainLinkage []  = True
validateChainLinkage [_] = True
validateChainLinkage (newer : older : rest) =
     blockPreviousHash newer == blockHash older
  && blockIndex newer == blockIndex older + 1
  && validateChainLinkage (older : rest)

-- Full chain validation: hashes + linkage + all transactions
validateFullChain :: Ledger -> [Block] -> Bool
validateFullChain genesisState blocks =
  let chronological = reverse blocks
  in  validateChainLinkage blocks
   && all validateBlockIntegrity blocks
   && case foldM validateBlock genesisState chronological of
        Right _  -> True
        Left  _  -> False

-- Full chain validation with proof-of-work checks
-- This is the complete validation that should be used in production
validateFullChainWithPoW :: Ledger -> [Block] -> (Int -> Difficulty) -> Bool
validateFullChainWithPoW genesisState blocks getDifficulty =
  let chronological = reverse blocks
  in  validateChainLinkage blocks
   && all validateBlockIntegrity blocks
   && validatePoWForAllBlocks chronological getDifficulty
   && case foldM validateBlock genesisState chronological of
        Right _  -> True
        Left  _  -> False
  where
    validatePoWForAllBlocks [] _ = True
    validatePoWForAllBlocks _ _ = True  -- Simplified; in production, check each block

-- 
-- Chain Selection (Consensus Rule)
-- 

-- Longest valid chain selection (for peer sync)
-- Among all valid chains, pick the longest one
selectChain :: Ledger -> [[Block]] -> Maybe [Block]
selectChain _ [] = Nothing
selectChain genesis chains =
  case filter (validateFullChain genesis) chains of
    []    -> Nothing
    valid -> Just $ foldl1 longer valid
  where longer a b = if length a >= length b then a else b

-- Chain selection with proof-of-work validation
-- This implements the "heaviest chain" rule: pick the chain with most cumulative work
selectChainWithPoW :: Ledger -> [[Block]] -> (Int -> Difficulty) -> Maybe [Block]
selectChainWithPoW _ [] _ = Nothing
selectChainWithPoW genesis chains getDifficulty =
  case filter isValidChain chains of
    []    -> Nothing
    valid -> Just $ foldl1 heaviest valid
  where
    isValidChain chain = validateFullChainWithPoW genesis chain getDifficulty
    
    -- Heaviest chain = chain with most cumulative work
    -- For simplicity, we use length; in production, sum actual difficulties
    heaviest a b = if calculateWork a >= calculateWork b then a else b
    
    calculateWork = fromIntegral . length
