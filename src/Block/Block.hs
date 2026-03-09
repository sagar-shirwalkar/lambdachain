{-# LANGUAGE DeriveGeneric #-}

module Block.Block
  ( Block(..)
  , genesisBlock
  , createBlock
  , calculateBlockHash
  , verifyBlockHash
  ) where

import Transaction.Transaction (BlockchainTx(..))
import ZKP.ZKP               (ZKP(..))
import qualified Crypto.Hash as H
import qualified Data.ByteString.Char8 as BC
import Data.Aeson             (ToJSON, FromJSON)
import GHC.Generics           (Generic)
import Data.Time.Clock.POSIX  (getPOSIXTime)

data Block = Block
  { blockIndex        :: !Int
  , blockTimestamp     :: !Integer
  , blockTransactions :: ![BlockchainTx]
  , blockPreviousHash :: !String
  , blockHash         :: !String
  } deriving (Show, Eq, Generic)

instance ToJSON Block
instance FromJSON Block

-- Hash of block contents (SHA-256).
calculateBlockHash :: Int -> Integer -> [BlockchainTx] -> String -> String
calculateBlockHash idx ts txs prevHash =
  let canonical = BC.pack $ concat
        [ "blk|ix:", show idx
        , "|ts:", show ts
        , "|ph:", prevHash
        , "|n:", show (length txs)
        , "|txs:", concatMap txFingerprint txs
        ]
      digest = H.hash canonical :: H.Digest H.SHA256
  in show digest
  where
    txFingerprint tx =
      let p = txProof tx
      in concat
           [ "{", txSender tx, ","
           , txRecipient tx, ","
           , show (txAmount tx), ","
           , show (txNonce tx), ","
           , zkpCommitment p, ","
           , zkpChallenge p, ","
           , zkpResponse p, "}"
           ]

verifyBlockHash :: Block -> Bool
verifyBlockHash b =
  blockHash b == calculateBlockHash
    (blockIndex b) (blockTimestamp b)
    (blockTransactions b) (blockPreviousHash b)

genesisBlock :: Block
genesisBlock =
  let idx = 0; ts = 0; txs = []; prev = replicate 64 '0'
  in Block idx ts txs prev (calculateBlockHash idx ts txs prev)

createBlock :: Int -> [BlockchainTx] -> String -> IO Block
createBlock idx txs prevHash = do
  ts <- round <$> getPOSIXTime
  return $ Block idx ts txs prevHash
    (calculateBlockHash idx ts txs prevHash)