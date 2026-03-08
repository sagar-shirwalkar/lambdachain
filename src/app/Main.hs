{-# LANGUAGE OverloadedStrings #-}

module Main where

import Network.Wai
import Network.Wai.Handler.Warp
import Network.HTTP.Types
import qualified Data.ByteString()
import qualified Data.ByteString.Lazy ()
import Data.Aeson
import GHC.Generics()

import Blockchain.Blockchain
import Block.Block()
import Consensus.Consensus()

-- Main entry point
main :: IO ()
main = run 3000 app

-- Application
app :: Application
app req respond = 
  case pathInfo req of
    ["blockchain"] -> handleGetBlockchain respond
    ["block"] -> handleAddBlock req respond
    ["validate"] -> handleValidate respond
    _ -> respond $ responseLBS status200 [("Content-Type", "application/json")] 
              (encode ("Welcome to LambdaChain Blockchain" :: String))

-- Get the current blockchain
handleGetBlockchain :: (Response -> IO a) -> IO a
handleGetBlockchain respond = 
  let bc = newBlockchain 4
  in respond $ responseLBS status200 [("Content-Type", "application/json")] 
              (encode (show (chain bc)))

-- Add a new block
handleAddBlock :: Request -> (Response -> IO a) -> IO a
handleAddBlock req respond = do
  body <- strictRequestBody req
  case decode body of
    Nothing -> respond $ responseLBS status400 [("Content-Type", "application/json")] "Invalid JSON"
    Just transactions -> 
      let bc = addBlock (newBlockchain 4) transactions
      in respond $ responseLBS status200 [("Content-Type", "application/json")] (encode (chain bc))

-- Validate the blockchain
handleValidate :: (Response -> IO a) -> IO a
handleValidate respond = 
  let bc = newBlockchain 4
      isValid = validateChain bc
  in respond $ responseLBS status200 [("Content-Type", "application/json")] 
              (encode isValid)
