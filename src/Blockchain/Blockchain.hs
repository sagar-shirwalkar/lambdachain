{-# LANGUAGE DeriveGeneric #-}

module Blockchain.Blockchain
  ( Blockchain(..)
  , newBlockchain
  , registerAccount
  , registerAccountFromSecret
  , submitTransaction
  , mineBlock
  , addReceivedBlock
  , adoptLongerChain
  , validateChain
  , getBalance
  , getAccount
  , chainLength
  , latestBlock
  ) where

import Block.Block
import qualified Transaction.Transaction as Tx
import Transaction.Transaction
    ( BlockchainTx(..)
    , AccountState(..)
    , Ledger
    , Address
    , TxValidationError(..)
    , verifyTransaction
    , processTransaction
    )
import Consensus.Consensus
    ( Difficulty
    , defaultDifficulty
    , createCoinbaseTx
    , miningReward
    , validateBlock
    , validateFullChain
    )
import qualified Consensus.Consensus as Consensus (mineBlock)
import Data.Time.Clock.POSIX (getPOSIXTime)
import qualified Data.Map.Strict as Map
import Data.List (foldl')
import Control.Monad (foldM)
import Data.Aeson (ToJSON, FromJSON)
import GHC.Generics (Generic)

data Blockchain = Blockchain
  { chain         :: ![Block]
  , ledger        :: !Ledger
  , pendingPool   :: ![BlockchainTx]
  , genesisLedger :: !Ledger
  } deriving (Show, Eq, Generic)

instance ToJSON Blockchain
instance FromJSON Blockchain

newBlockchain :: Blockchain
newBlockchain = Blockchain
  { chain         = [genesisBlock]
  , ledger        = Tx.emptyLedger
  , pendingPool   = []
  , genesisLedger = Tx.emptyLedger
  }

-- Register with public key (production)
registerAccount :: Integer -> Integer -> Blockchain -> Blockchain
registerAccount pubKey balance bc =
  bc { ledger = Tx.registerAccountWithPK pubKey balance (ledger bc) }

-- Register with secret key (debug)
registerAccountFromSecret :: Integer -> Integer -> Blockchain -> Blockchain
registerAccountFromSecret secret balance bc =
  bc { ledger = Tx.registerAccount secret balance (ledger bc) }

-- Validate and add transaction to pending pool
submitTransaction :: Blockchain -> BlockchainTx -> Either TxValidationError Blockchain
submitTransaction bc tx = do
  verifyTransaction (ledger bc) tx
  Right bc { pendingPool = pendingPool bc ++ [tx] }

-- Mine pending transactions into a new block with proof-of-work
-- This function creates a coinbase transaction for the miner and performs PoW mining
mineBlock :: Blockchain          -- Current blockchain state
          -> Address             -- Miner's address for reward
          -> Difficulty          -- Mining difficulty
          -> IO (Either String Blockchain)
mineBlock bc minerAddress difficulty
  | null (pendingPool bc) = return (Left "No pending transactions")
  | otherwise = do
      let prevBlock = latestBlock bc
          newIndex  = blockIndex prevBlock + 1
          reward    = miningReward newIndex
      
      -- Create coinbase transaction for miner
      coinbaseTx <- createCoinbaseTx minerAddress reward newIndex
      
      -- Combine coinbase with pending transactions
      let allTxs = coinbaseTx : pendingPool bc
          (validTxs, newLedger) = applyValid (ledger bc) allTxs
      
      if null validTxs
        then return (Left "No valid transactions in pool")
        else do
          timestamp <- getCurrentTimestamp
          
          -- Create block template (nonce will be found by PoW)
          let blockTemplate = Block
                { blockIndex        = newIndex
                , blockTimestamp     = timestamp
                , blockTransactions = validTxs
                , blockPreviousHash  = blockHash prevBlock
                , blockNonce        = 0  -- Will be replaced by mining
                , blockHash         = "" -- Will be calculated by mining
                }
          
          -- Perform proof-of-work mining (max 10 million attempts)
          minedResult <- Consensus.mineBlock blockTemplate difficulty 10000000
          
          case minedResult of
            Nothing -> return (Left "Mining failed: could not find valid nonce")
            Just minedBlock -> return $ Right bc
              { chain       = minedBlock : chain bc
              , ledger      = newLedger
              , pendingPool = []
              }

-- Apply transactions one by one, skip invalid.
applyValid :: Ledger -> [BlockchainTx] -> ([BlockchainTx], Ledger)
applyValid startL txs =
  let (rev, finalL) = foldl' go ([], startL) txs
  in (reverse rev, finalL)
  where
    go (acc, l) tx = case processTransaction l tx of
      Right l' -> (tx : acc, l')
      Left  _  -> (acc, l)

-- Add a block received from a peer.
addReceivedBlock :: Blockchain -> Block -> Either String Blockchain
addReceivedBlock bc block
  | not (verifyBlockHash block) =
      Left "Invalid block hash"
  | blockPreviousHash block /= blockHash (latestBlock bc) =
      Left "Block does not link to chain tip"
  | blockIndex block /= blockIndex (latestBlock bc) + 1 =
      Left "Invalid block index"
  | otherwise =
      case validateBlock (ledger bc) block of
        Left err -> Left $ "Tx validation failed: " ++ show err
        Right newL -> Right bc
          { chain       = block : chain bc
          , ledger      = newL
          , pendingPool = filter (`notElem` blockTransactions block)
                            (pendingPool bc)
          }

-- Adopt a remote chain if longer and valid.
adoptLongerChain :: Blockchain -> [Block] -> Blockchain
adoptLongerChain bc remote
  | length remote <= length (chain bc) = bc
  | not (validateFullChain (genesisLedger bc) remote) = bc
  | otherwise =
      case foldM validateBlock (genesisLedger bc) (reverse remote) of
        Right newL -> bc { chain = remote, ledger = newL }
        Left _     -> bc

validateChain :: Blockchain -> Bool
validateChain bc = validateFullChain (ledger bc) (chain bc)

getBalance :: Blockchain -> Address -> Maybe Integer
getBalance bc addr = accountBalance <$> Map.lookup addr (ledger bc)

getAccount :: Blockchain -> Address -> Maybe AccountState
getAccount bc addr = Map.lookup addr (ledger bc)

chainLength :: Blockchain -> Int
chainLength = length . chain

latestBlock :: Blockchain -> Block
latestBlock bc = case chain bc of
  (b:_) -> b
  []    -> genesisBlock

getCurrentTimestamp :: IO Integer
getCurrentTimestamp = round <$> getPOSIXTime
