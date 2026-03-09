module Consensus.Consensus
  ( validateBlock
  , validateBlockIntegrity
  , validateChainLinkage
  , validateFullChain
  , selectChain
  , miningReward
  ) where

import Block.Block
import Transaction.Transaction
    ( TxValidationError(..)
    , processTransactionWithoutNonce
    , Ledger
    )
import Control.Monad (foldM)

-- Validate & apply every transaction in a block sequentially - returns updated ledger or first error
-- Skips nonce check since these transactions have already been mined
validateBlock :: Ledger -> Block -> Either TxValidationError Ledger
validateBlock ledger block =
  foldM processTransactionWithoutNonce ledger (blockTransactions block)

-- Hash integrity check.
validateBlockIntegrity :: Block -> Bool
validateBlockIntegrity = verifyBlockHash

-- Chain linkage (list stored newest-first) for O(1)
validateChainLinkage :: [Block] -> Bool
validateChainLinkage []  = True
validateChainLinkage [_] = True
validateChainLinkage (newer : older : rest) =
     blockPreviousHash newer == blockHash older
  && blockIndex newer == blockIndex older + 1
  && validateChainLinkage (older : rest)

-- Full chain validation: hashes + linkage + all ZKP proofs
validateFullChain :: Ledger -> [Block] -> Bool
validateFullChain genesisState blocks =
  let chronological = reverse blocks
  in  validateChainLinkage blocks
   && all validateBlockIntegrity blocks
   && case foldM validateBlock genesisState chronological of
        Right _  -> True
        Left  _  -> False

-- Longest valid chain selection (for peer sync)
selectChain :: Ledger -> [[Block]] -> Maybe [Block]
selectChain _ [] = Nothing
selectChain genesis chains =
  case filter (validateFullChain genesis) chains of
    []    -> Nothing
    valid -> Just $ foldl1 longer valid
  where longer a b = if length a >= length b then a else b

-- Block reward with halving
miningReward :: Int -> Double
miningReward height = 50.0 / (2.0 ^ (height `div` 210000))