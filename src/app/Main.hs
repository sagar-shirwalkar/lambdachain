{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Network.Wai
import Network.Wai.Handler.Warp    (run)
import Network.HTTP.Types

import Control.Concurrent.STM

import Data.Aeson
import qualified Data.Text as T
import GHC.Generics                (Generic)

import Blockchain.Blockchain
    ( Blockchain(..)
    , newBlockchain
    , registerAccount          -- operates on Blockchain
    , registerAccountFromSecret
    , getAccount
    , submitTransaction
    , mineBlock
    , validateChain
    , chainLength
    , latestBlock
    )
import Transaction.Transaction
    ( BlockchainTx(..)
    , AccountState(..)
    , deriveAddress
    , deriveAddressFromSecret
    , createTransaction
    , createEncryptedTransaction
    )
import Block.Block                 (Block(..))
import ZKP.ZKP

--
-- Request types
--

data RegisterRequest = RegisterRequest
  { rrPublicKey      :: String
  , rrInitialBalance :: Integer
  } deriving (Show, Generic)

instance FromJSON RegisterRequest where
  parseJSON = withObject "RegisterRequest" $ \v ->
    RegisterRequest <$> v .: "publicKey"
                    <*> v .: "initialBalance"

data DebugRegisterRequest = DebugRegisterRequest
  { drrSecretKey      :: Integer
  , drrInitialBalance :: Integer
  } deriving (Show, Generic)

instance FromJSON DebugRegisterRequest where
  parseJSON = withObject "DebugRegisterRequest" $ \v ->
    DebugRegisterRequest <$> v .: "secretKey"
                         <*> v .: "initialBalance"

data DebugTxRequest = DebugTxRequest
  { dtrSenderSecret :: Integer
  , dtrRecipient    :: String
  , dtrAmount       :: Integer
  , dtrMemo         :: Maybe String     -- optional encrypted memo
  , dtrEncKey       :: Maybe String     -- symmetric key for memo
  } deriving (Show, Generic)

instance FromJSON DebugTxRequest where
  parseJSON = withObject "DebugTxRequest" $ \v ->
    DebugTxRequest <$> v .: "senderSecret"
                   <*> v .: "recipient"
                   <*> v .: "amount"
                   <*> v .:? "memo"
                   <*> v .:? "encKey"

--
-- Response helpers
--

jsonHeader :: ResponseHeaders
jsonHeader = [("Content-Type", "application/json")]

jsonOk :: ToJSON a => a -> Response
jsonOk = responseLBS status200 jsonHeader . encode

jsonCreated :: ToJSON a => a -> Response
jsonCreated = responseLBS status201 jsonHeader . encode

jsonErr :: Status -> String -> Response
jsonErr st msg = responseLBS st jsonHeader $
  encode (object ["error" .= msg])

--
-- Entry point
--

main :: IO ()
main = do
  putStrLn "LambdaChain starting on port 3000..."
  stateVar <- newTVarIO newBlockchain
  run 3000 (app stateVar)

--
-- Router
--

app :: TVar Blockchain -> Application
app st req respond =
  case (requestMethod req, pathInfo req) of
    -- Public API
    ("GET",  [])                   -> respond $ jsonOk ("LambdaChain Blockchain — ZKP Consensus" :: String)
    ("GET",  ["blockchain"])       -> handleGetBlockchain   st respond
    ("GET",  ["ledger"])           -> handleGetLedger        st respond
    ("GET",  ["balance", addr])    -> handleGetBalance       st (T.unpack addr) respond
    ("GET",  ["pending"])          -> handleGetPending        st respond
    ("GET",  ["validate"])         -> handleValidate          st respond

    -- Production endpoints (client creates ZKP locally)
    ("POST", ["register"])         -> handleRegister          st req respond
    ("POST", ["transaction"])      -> handleSubmitTx          st req respond
    ("POST", ["mine"])             -> handleMine              st respond

    -- Debug endpoints (server handles keys — NEVER use in production)
    ("POST", ["debug", "register"])    -> handleDebugRegister st req respond
    ("POST", ["debug", "transaction"]) -> handleDebugTx       st req respond

    _ -> respond $ jsonErr status404 "Not found"

--
-- GET handlers
--

handleGetBlockchain :: TVar Blockchain -> (Response -> IO a) -> IO a
handleGetBlockchain st respond = do
  bc <- readTVarIO st
  respond $ jsonOk $ object
    [ "chainLength" .= chainLength bc
    , "latestBlock" .= latestBlock bc
    , "chain"       .= chain bc
    ]

handleGetLedger :: TVar Blockchain -> (Response -> IO a) -> IO a
handleGetLedger st respond = do
  bc <- readTVarIO st
  respond $ jsonOk (ledger bc)

handleGetBalance :: TVar Blockchain -> String -> (Response -> IO a) -> IO a
handleGetBalance st addr respond = do
  bc <- readTVarIO st
  case getAccount bc addr of
    Nothing   -> respond $ jsonErr status404 "Address not found"
    Just acct -> respond $ jsonOk $ object
      [ "address" .= addr
      , "balance" .= accountBalance acct
      , "nonce"   .= accountNonce acct
      , "pubKey"  .= toHex (accountPubKey acct)
      ]

handleGetPending :: TVar Blockchain -> (Response -> IO a) -> IO a
handleGetPending st respond = do
  bc <- readTVarIO st
  respond $ jsonOk $ object
    [ "count"        .= length (pendingPool bc)
    , "transactions" .= pendingPool bc
    ]

handleValidate :: TVar Blockchain -> (Response -> IO a) -> IO a
handleValidate st respond = do
  bc <- readTVarIO st
  let valid = validateChain bc
  respond $ jsonOk $ object
    [ "valid"       .= valid
    , "chainLength" .= chainLength bc
    ]

--
-- Production POST handlers
--

-- Register with a public key (hex-encoded).
handleRegister :: TVar Blockchain -> Request -> (Response -> IO a) -> IO a
handleRegister st req respond = do
  body <- strictRequestBody req
  case decode body of
    Nothing -> respond $ jsonErr status400 "Invalid JSON"
    Just rr -> do
      let pk   = fromHex (rrPublicKey rr)
          bal  = rrInitialBalance rr
          addr = deriveAddress pk
      atomically $ modifyTVar' st (registerAccount pk bal)
      respond $ jsonCreated $ object
        [ "message" .= ("Account registered" :: String)
        , "address" .= addr
        ]

-- Submit a pre-signed transaction (client built the ZKP).
handleSubmitTx :: TVar Blockchain -> Request -> (Response -> IO a) -> IO a
handleSubmitTx st req respond = do
  body <- strictRequestBody req
  case (eitherDecode body :: Either String BlockchainTx) of
    Left err -> respond $ jsonErr status400 ("Invalid transaction JSON: " ++ err)
    Right tx -> do
      result <- atomically $ do
        bc <- readTVar st
        case submitTransaction bc tx of
          Right bc' -> writeTVar st bc' >> return (Right ())
          Left err' -> return (Left err')
      case result of
        Right () -> respond $ jsonCreated $ object
          [ "message" .= ("Transaction accepted" :: String)
          , "sender"  .= txSender tx
          ]
        Left err' -> respond $ jsonErr status400 (show err')

-- Mine all valid pending transactions into a new block.
handleMine :: TVar Blockchain -> (Response -> IO a) -> IO a
handleMine st respond = do
  bc <- readTVarIO st
  result <- mineBlock bc
  case result of
    Left err -> respond $ jsonErr status400 err
    Right newBC -> do
      atomically $ writeTVar st newBC
      let blk = latestBlock newBC
      respond $ jsonCreated $ object
        [ "message"     .= ("Block mined" :: String)
        , "blockIndex"  .= blockIndex blk
        , "blockHash"   .= blockHash blk
        , "txCount"     .= length (blockTransactions blk)
        ]

--
-- Debug POST handlers  (secret keys sent to server - testing only!)
--

handleDebugRegister :: TVar Blockchain -> Request -> (Response -> IO a) -> IO a
handleDebugRegister st req respond = do
  body <- strictRequestBody req
  case decode body of
    Nothing -> respond $ jsonErr status400 "Invalid JSON"
    Just drr -> do
      let secret = drrSecretKey drr
          pk     = getPublicKey defaultParams secret
          addr   = deriveAddress pk
      atomically $ modifyTVar' st
        (registerAccountFromSecret secret (drrInitialBalance drr))
      respond $ jsonCreated $ object
        [ "message"   .= ("Account registered (debug)" :: String)
        , "address"   .= addr
        , "publicKey" .= toHex pk
        ]

handleDebugTx :: TVar Blockchain -> Request -> (Response -> IO a) -> IO a
handleDebugTx st req respond = do
  body <- strictRequestBody req
  case decode body of
    Nothing -> respond $ jsonErr status400 "Invalid JSON"
    Just dtr -> do
      bc <- readTVarIO st
      let secret     = dtrSenderSecret dtr
          senderAddr = deriveAddressFromSecret secret
      case getAccount bc senderAddr of
        Nothing -> respond $ jsonErr status404 "Sender not found"
        Just acct -> do
          let nonce = accountNonce acct + 1
          tx <- case (dtrMemo dtr, dtrEncKey dtr) of
            (Just memo, Just ek) ->
              createEncryptedTransaction secret (dtrRecipient dtr)
                (dtrAmount dtr) nonce memo ek
            _ ->
              createTransaction secret (dtrRecipient dtr)
                (dtrAmount dtr) nonce
          result <- atomically $ do
            currentBC <- readTVar st
            case submitTransaction currentBC tx of
              Right bc' -> writeTVar st bc' >> return (Right ())
              Left err  -> return (Left err)
          case result of
            Right () -> respond $ jsonCreated $ object
              [ "message" .= ("Transaction submitted (debug)" :: String)
              , "sender"  .= txSender tx
              , "nonce"   .= txNonce tx
              ]
            Left err -> respond $ jsonErr status400 (show err)