module Main (main) where

import Test.Hspec
import Test.QuickCheck
import Data.List (isPrefixOf)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import Block.Block
import Blockchain.Blockchain
import Consensus.Consensus
import Hash.Hash
import MerkleTree.MerkleTree
import Security.Security
import Security.HomomorphicEncryption
import ZKP.ZKP
import Crypto.PubKey.Ed25519 (SecretKey, PublicKey, toPublic, secretKey)
import Crypto.Error (CryptoFailable(..))

main :: IO ()
main = hspec $ do
  describe "Hash" $ do
    it "returns consistent hashes" $ do
      hashString "hello" `shouldBe` hashString "hello"
    it "returns different hashes for different inputs" $ do
      hashString "hello" `shouldNotBe` hashString "world"

  describe "MerkleTree" $ do
    it "constructs a tree from transactions" $ do
      let txs = ["tx1", "tx2"]
      let tree = constructMerkleTree txs
      case tree of
        Node hash _ _ -> hash `shouldNotBe` ""
        _ -> expectationFailure "Expected a Node"
    
    it "verifies a valid tree" $ do
      let txs = ["tx1", "tx2", "tx3", "tx4"]
      let tree = constructMerkleTree txs
      verifyMerkleTree tree `shouldBe` True

  describe "Block" $ do
    it "calculates block hash deterministically" $ do
      let block = constructBlock 1 123456 ["tx1"] "prevHash" 0 "hash"
      calculateBlockHash block `shouldBe` calculateBlockHash block

  describe "Blockchain" $ do
    it "creates a new blockchain with genesis block" $ do
      let bc = newBlockchain 1
      length (chain bc) `shouldBe` 1
      let genesis = head (chain bc)
      blockIndex genesis `shouldBe` 0

    it "adds a block to the blockchain" $ do
      let bc = newBlockchain 1
      let bc2 = addBlock bc ["tx1"]
      length (chain bc2) `shouldBe` 2
      let latest = head (chain bc2)
      blockIndex latest `shouldBe` 1
      blockTransactions latest `shouldBe` ["tx1"]

    it "validates a valid chain" $ do
      let bc = newBlockchain 1
      let bc2 = addBlock bc ["tx1"]
      validateChain bc2 `shouldBe` True

  describe "Consensus" $ do
    it "validates proof of work" $ do
      let difficulty = 1
      let bc = newBlockchain difficulty
      let bc2 = addBlock bc ["tx1"]
      let latest = head (chain bc2)
      let target = replicate difficulty '0'
      take difficulty (blockHash latest) `shouldBe` target

  describe "Security" $ do
    it "encrypts and decrypts data with AES-GCM" $ do
      let key = "testkey1234567890testkey12345678"
      let plaintext = "sensitive data"
      let encrypted = encryptData plaintext key
      decryptData key encrypted `shouldBe` plaintext

    it "verifies private transaction ZKP with Ed25519" $ do
      let seed = B.replicate 32 0
      case secretKey seed of
        CryptoPassed sk -> do
          let pk = toPublic sk
          let tx = "tx"
          let zkp = generateEd25519ZKProof (BC.pack tx) sk
          verifyEd25519ZKP zkp pk `shouldBe` True
        CryptoFailed err -> expectationFailure $ "Failed to create secret key: " ++ show err
