module Network.Network where

import Network.Socket
import Network.Socket.ByteString
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Block.Block
import Data.Aeson
import qualified Data.ByteString.Lazy as BSL

-- Establish a connection to a peer
connectToPeer :: String -> Int -> IO Socket
connectToPeer host port = do
  addr <- getAddrInfo Nothing (Just host) (Just (show port))
  sock <- socket (addrFamily (head addr)) Stream defaultProtocol
  connect sock (addrAddress (head addr))
  return sock

-- Send a block to a peer
sendBlock :: Socket -> Block -> IO ()
sendBlock sock block = do
  let encoded = encodeBlock block
  sendAll sock (BSL.toStrict encoded)

-- Receive a block from a peer
receiveBlock :: Socket -> IO Block
receiveBlock sock = do
  msg <- recv sock 4096
  return (decodeBlock msg)

-- Encode a block to ByteString
encodeBlock :: Block -> BSL.ByteString
encodeBlock block = encode block

-- Decode a block from ByteString
decodeBlock :: BS.ByteString -> Block
decodeBlock bs = 
  case decode (BSL.fromStrict bs) of
    Just block -> block
    Nothing -> error "Failed to decode block"

-- Broadcast a block to multiple peers
broadcastBlock :: [Socket] -> Block -> IO ()
broadcastBlock peers block = 
  mapM_ (\sock -> sendBlock sock block) peers
