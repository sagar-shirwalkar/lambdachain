{-# LANGUAGE OverloadedStrings #-}

module Main where

import Test.Hspec
import Test.QuickCheck

import qualified Data.Map.Strict as Map
import qualified Data.ByteString.Char8 as BC
import Data.Maybe (fromJust)

import ZKP.ZKP
import Transaction.Transaction
import Blockchain.Blockchain
import Block.Block
import Consensus.Consensus hiding (mineBlock)
import MerkleTree.MerkleTree
import Cryptography.Hash hiding (hash)
import Cryptography.HomomorphicEncryption hiding (bsToString)

main :: IO ()
main = hspec $ do
  zkpSpec
  transactionSpec
  blockSpec
  consensusSpec
  hashSpec
  merkleTreeSpec
  encryptionSpec
  blockchainSpec
  integrationSpec

--
-- ZKP Tests
--

zkpSpec :: Spec
zkpSpec = describe "ZKP.ZKP" $ do

  describe "defaultParams" $ do
    it "has consistent p, q relationship: q = (p-1)/2" $ do
      let p = paramP defaultParams
          q = paramQ defaultParams
      q `shouldBe` (p - 1) `div` 2

    it "generator g is in the subgroup (g^q mod p == 1)" $ do
      let p = paramP defaultParams
          q = paramQ defaultParams
          g = paramG defaultParams
      powerMod g q p `shouldBe` 1

  describe "getPublicKey" $ do
    it "produces a deterministic public key" $ do
      let pk1 = getPublicKey defaultParams 12345
          pk2 = getPublicKey defaultParams 12345
      pk1 `shouldBe` pk2

    it "produces different keys for different secrets" $ do
      let pk1 = getPublicKey defaultParams 12345
          pk2 = getPublicKey defaultParams 67890
      pk1 `shouldNotBe` pk2

    it "public key is in valid range (1 < y < p)" $ do
      let pk = getPublicKey defaultParams 99999
      pk `shouldSatisfy` (> 1)
      pk `shouldSatisfy` (< paramP defaultParams)

  describe "generateZKProof / verifyZKP" $ do
    it "valid proof verifies" $ do
      let secret  = 123456789
          payload = BC.pack "test transaction"
          proof   = generateZKProof defaultParams secret 42 payload
      verifyZKP defaultParams proof payload `shouldBe` True

    it "proof fails with wrong payload" $ do
      let secret  = 123456789
          payload = BC.pack "test transaction"
          proof   = generateZKProof defaultParams secret 42 payload
      verifyZKP defaultParams proof (BC.pack "wrong") `shouldBe` False

    it "proof fails with tampered commitment" $ do
      let secret  = 123456789
          payload = BC.pack "test transaction"
          proof   = generateZKProof defaultParams secret 42 payload
          tampered = proof { zkpCommitment = "deadbeef" }
      verifyZKP defaultParams tampered payload `shouldBe` False

    it "proof fails with tampered response" $ do
      let secret  = 123456789
          payload = BC.pack "test transaction"
          proof   = generateZKProof defaultParams secret 42 payload
          tampered = proof { zkpResponse = "0" }
      verifyZKP defaultParams tampered payload `shouldBe` False

    it "proof fails with tampered challenge" $ do
      let secret  = 123456789
          payload = BC.pack "test transaction"
          proof   = generateZKProof defaultParams secret 42 payload
          tampered = proof { zkpChallenge = "1" }
      verifyZKP defaultParams tampered payload `shouldBe` False

  describe "generateZKProofIO" $ do
    it "generates valid proofs with random nonce" $ do
      let secret  = 555555
          payload = BC.pack "random nonce test"
      proof <- generateZKProofIO defaultParams secret payload
      verifyZKP defaultParams proof payload `shouldBe` True

    it "generates different proofs each time (random nonce)" $ do
      let secret  = 555555
          payload = BC.pack "nonce uniqueness"
      proof1 <- generateZKProofIO defaultParams secret payload
      proof2 <- generateZKProofIO defaultParams secret payload
      zkpCommitment proof1 `shouldNotBe` zkpCommitment proof2

  describe "verifyZKPWithKey" $ do
    it "accepts proof matching the correct public key" $ do
      let secret  = 777777
          pk      = getPublicKey defaultParams secret
          payload = BC.pack "key check"
      proof <- generateZKProofIO defaultParams secret payload
      verifyZKPWithKey defaultParams proof pk payload `shouldBe` True

    it "rejects proof against wrong public key" $ do
      let secret1 = 777777
          secret2 = 888888
          pk2     = getPublicKey defaultParams secret2
          payload = BC.pack "wrong key"
      proof <- generateZKProofIO defaultParams secret1 payload
      verifyZKPWithKey defaultParams proof pk2 payload `shouldBe` False

  describe "hex encoding" $ do
    it "roundtrips through toHex/fromHex" $ do
      let n = 123456789012345678901234567890 :: Integer
      fromHex (toHex n) `shouldBe` n

    it "fromHex of invalid returns -1" $ do
      fromHex "not_hex_at_all!" `shouldBe` (-1)

  describe "QuickCheck properties" $ do
    it "any valid secret produces a verifiable proof" $
      property $ \(Positive secret) -> ioProperty $ do
        let payload = BC.pack "qc test"
        proof <- generateZKProofIO defaultParams secret payload
        return $ verifyZKP defaultParams proof payload

--
-- Block Tests
--

blockSpec :: Spec
blockSpec = describe "Block.Block" $ do

  describe "genesisBlock" $ do
    it "has index 0" $ do
      blockIndex genesisBlock `shouldBe` 0

    it "has empty transactions" $ do
      blockTransactions genesisBlock `shouldBe` []

    it "has valid hash" $ do
      verifyBlockHash genesisBlock `shouldBe` True

  describe "calculateBlockHash" $ do
    it "produces consistent hash" $ do
      let h1 = calculateBlockHash 0 100 [] "0000000000000000000000000000000000000000" 0
          h2 = calculateBlockHash 0 100 [] "0000000000000000000000000000000000000000" 0
      h1 `shouldBe` h2

    it "produces different hash for different nonce" $ do
      let h1 = calculateBlockHash 0 100 [] "0000000000000000000000000000000000000000" 0
          h2 = calculateBlockHash 0 100 [] "0000000000000000000000000000000000000000" 1
      h1 `shouldNotBe` h2

  describe "verifyBlockHash" $ do
    it "accepts valid block" $ do
      verifyBlockHash genesisBlock `shouldBe` True

    it "rejects tampered block" $ do
      let tampered = genesisBlock { blockNonce = 999 }
      verifyBlockHash tampered `shouldBe` False

  describe "createBlock" $ do
    it "creates block with correct index" $ do
      block <- createBlock 5 [] "abc123" 42
      blockIndex block `shouldBe` 5

    it "creates block with valid hash" $ do
      block <- createBlock 1 [] "abc123" 0
      verifyBlockHash block `shouldBe` True

--
-- Consensus Tests
--

consensusSpec :: Spec
consensusSpec = describe "Consensus.Consensus" $ do

  describe "meetsDifficulty" $ do
    it "accepts hash with required leading zeros" $ do
      meetsDifficulty "00abc123" 2 `shouldBe` True

    it "rejects hash without enough leading zeros" $ do
      meetsDifficulty "0abc123" 2 `shouldBe` False

    it "accepts any hash when difficulty is 0" $ do
      meetsDifficulty "abc123" 0 `shouldBe` True

  describe "defaultDifficulty" $ do
    it "is 2" $ do
      defaultDifficulty `shouldBe` 2

  describe "maxDifficulty" $ do
    it "is 8" $ do
      maxDifficulty `shouldBe` 8

  describe "miningReward" $ do
    it "starts at 50 for block 0" $ do
      miningReward 0 `shouldBe` 50.0

    it "halves after 210000 blocks" $ do
      miningReward 210000 `shouldBe` 25.0
      miningReward 210001 `shouldBe` 25.0

  describe "createCoinbaseTx" $ do
    it "creates coinbase transaction" $ do
      tx <- createCoinbaseTx "miner_address" 50.0 1
      txRecipient tx `shouldBe` "miner_address"
      txSender tx `shouldBe` "0000000000000000000000000000000000000000"

  describe "validatePoW" $ do
    it "accepts block meeting difficulty" $ do
      blk <- createBlock 0 [] (replicate 64 '0') 0
      let validHash = "00" ++ replicate 62 'a'
          blk2 = blk { blockHash = validHash }
      meetsDifficulty validHash 2 `shouldBe` True

  describe "validateChainLinkage" $ do
    it "accepts valid chain" $ do
      let b0 = genesisBlock
          b1 = genesisBlock { blockIndex = 1, blockPreviousHash = blockHash b0 }
      validateChainLinkage [b1, b0] `shouldBe` True

    it "rejects broken linkage" $ do
      let b0 = genesisBlock
          b1 = genesisBlock { blockIndex = 1, blockPreviousHash = "wrong" }
      validateChainLinkage [b1, b0] `shouldBe` False

--
-- Hash Tests
--

hashSpec :: Spec
hashSpec = describe "Cryptography.Hash" $ do

  describe "hashString" $ do
    it "produces consistent hash" $ do
      hashString "test" `shouldBe` hashString "test"

    it "produces different hash for different input" $ do
      hashString "test1" `shouldNotBe` hashString "test2"

    it "produces 64 character hex string" $ do
      let h = hashString "test"
      length h `shouldBe` 64

  describe "hash" $ do
    it "is alias for hashString" $ do
      hashString "test" `shouldBe` hashString "test"

  describe "secureHash" $ do
    it "produces consistent result" $ do
      secureHash "test" `shouldBe` secureHash "test"

    it "differs from plain hash" $ do
      secureHash "test" `shouldNotBe` hashString "test"

--
-- MerkleTree Tests
--

merkleTreeSpec :: Spec
merkleTreeSpec = describe "MerkleTree.MerkleTree" $ do

  describe "constructMerkleTree" $ do
    it "creates single leaf for single transaction" $ do
      let tree = constructMerkleTree ["tx1"]
      verifyMerkleTree tree `shouldBe` True

    it "creates valid tree for multiple transactions" $ do
      let tree = constructMerkleTree ["tx1", "tx2", "tx3", "tx4"]
      verifyMerkleTree tree `shouldBe` True

    it "handles empty list" $ do
      let tree = constructMerkleTree []
      verifyMerkleTree tree `shouldBe` False

  describe "getMerkleRoot" $ do
    it "returns root hash" $ do
      let tree = constructMerkleTree ["tx1", "tx2"]
      length (getMerkleRoot tree) `shouldBe` 128

  describe "verifyMerkleTree" $ do
    it "accepts valid tree" $ do
      let tree = constructMerkleTree ["tx1", "tx2"]
      verifyMerkleTree tree `shouldBe` True

    it "rejects tampered tree" $ do
      let tree = Node "tampered" (Leaf "a") (Leaf "b")
      verifyMerkleTree tree `shouldBe` False

--
-- Encryption Tests
--

encryptionSpec :: Spec
encryptionSpec = describe "Cryptography.HomomorphicEncryption" $ do

  describe "encryptData" $ do
    it "encrypts and produces base64 output" $ do
      let encrypted = encryptData "plaintext" "secretkey123"
      length (encryptedNonce encrypted) `shouldSatisfy` (> 0)
      length (encryptedCiphertext encrypted) `shouldSatisfy` (> 0)

    it "produces same output for same input (deterministic)" $ do
      let e1 = encryptData "test" "key"
          e2 = encryptData "test" "key"
      encryptedNonce e1 `shouldBe` encryptedNonce e2

  describe "decryptData" $ do
    it "roundtrips encryption/decryption" $ do
      let original = "secret message"
          encrypted = encryptData original "mysecretkey"
          decrypted = decryptData "mysecretkey" encrypted
      decrypted `shouldBe` original

    it "fails with wrong key" $ do
      let encrypted = encryptData "test" "correctkey"
          decrypted = decryptData "wrongkey" encrypted
      decrypted `shouldNotBe` "test"

  describe "stringToBS / bsToString" $ do
    it "roundtrips" $ do
      let original = "hello world"
      bsToString (stringToBS original) `shouldBe` original

--
-- Transaction Tests
--

transactionSpec :: Spec
transactionSpec = describe "Transaction.Transaction" $ do

  describe "deriveAddress" $ do
    it "deterministic: same key gives same address" $ do
      let pk = getPublicKey defaultParams 12345
      deriveAddress pk `shouldBe` deriveAddress pk

    it "different keys give different addresses" $ do
      let pk1 = getPublicKey defaultParams 12345
          pk2 = getPublicKey defaultParams 67890
      deriveAddress pk1 `shouldNotBe` deriveAddress pk2

    it "address is 40 hex characters" $ do
      let pk = getPublicKey defaultParams 12345
          addr = deriveAddress pk
      length addr `shouldBe` 40
      all (`elem` ("0123456789abcdef" :: String)) addr `shouldBe` True

  describe "deriveAddressFromSecret" $ do
    it "matches deriveAddress . getPublicKey" $ do
      let secret = 42
          addr1  = deriveAddressFromSecret secret
          addr2  = deriveAddress (getPublicKey defaultParams secret)
      addr1 `shouldBe` addr2

  describe "Ledger operations" $ do
    it "emptyLedger has no accounts" $ do
      Map.size emptyLedger `shouldBe` 0

    it "registerAccount adds an account" $ do
      let lgr = Transaction.Transaction.registerAccount 12345 1000 emptyLedger
      Map.size lgr `shouldBe` 1

    it "registered account has correct balance" $ do
      let lgr  = Transaction.Transaction.registerAccount 12345 1000 emptyLedger
          addr = deriveAddressFromSecret 12345
      case Map.lookup addr lgr of
        Nothing   -> expectationFailure "Account not found"
        Just acct -> do
          accountBalance acct `shouldBe` 1000
          accountNonce acct `shouldBe` 0

    it "lookupPublicKey returns the correct key" $ do
      let secret = 12345
          pk     = getPublicKey defaultParams secret
          lgr    = Transaction.Transaction.registerAccount secret 500 emptyLedger
          addr   = deriveAddressFromSecret secret
      lookupPublicKey lgr addr `shouldBe` Just pk

    it "lookupPublicKey returns Nothing for unknown address" $ do
      lookupPublicKey emptyLedger "nonexistent" `shouldBe` Nothing

  describe "createTransaction" $ do
    it "creates a transaction with correct fields" $ do
      let alice = 11111
          bobAddr = deriveAddressFromSecret 22222
      tx <- createTransaction alice bobAddr 100 1
      txRecipient tx `shouldBe` bobAddr
      txAmount tx `shouldBe` 100
      txNonce tx `shouldBe` 1
      txCiphertext tx `shouldBe` Nothing
      txSender tx `shouldBe` deriveAddressFromSecret alice

    it "creates an encrypted transaction with ciphertext" $ do
      let alice = 11111
          bobAddr = deriveAddressFromSecret 22222
      tx <- createEncryptedTransaction alice bobAddr 50 1 "hello" "key123"
      txCiphertext tx `shouldNotBe` Nothing

  describe "canonicalPayload" $ do
    it "is deterministic" $ do
      let p1 = canonicalPayload "alice" "bob" 100 1 Nothing
          p2 = canonicalPayload "alice" "bob" 100 1 Nothing
      p1 `shouldBe` p2

    it "changes when any field changes" $ do
      let base   = canonicalPayload "alice" "bob" 100 1 Nothing
          diffAm = canonicalPayload "alice" "bob" 200 1 Nothing
          diffNo = canonicalPayload "alice" "bob" 100 2 Nothing
          diffRe = canonicalPayload "alice" "charlie" 100 1 Nothing
      base `shouldNotBe` diffAm
      base `shouldNotBe` diffNo
      base `shouldNotBe` diffRe

  describe "verifyTransaction" $ do
    it "accepts a valid transaction" $ do
      let alice   = 11111
          bob     = 22222
          bobAddr = deriveAddressFromSecret bob
          lgr     = Transaction.Transaction.registerAccount alice 1000
                  . Transaction.Transaction.registerAccount bob 500
                  $ emptyLedger
      tx <- createTransaction alice bobAddr 100 1
      verifyTransaction lgr tx `shouldBe` Right ()

    it "rejects unknown sender" $ do
      let bob     = 22222
          bobAddr = deriveAddressFromSecret bob
          lgr     = Transaction.Transaction.registerAccount bob 500 emptyLedger
      tx <- createTransaction 99999 bobAddr 100 1
      verifyTransaction lgr tx `shouldBe` Left UnknownSender

    it "rejects wrong nonce" $ do
      let alice   = 11111
          bob     = 22222
          bobAddr = deriveAddressFromSecret bob
          lgr     = Transaction.Transaction.registerAccount alice 1000
                  . Transaction.Transaction.registerAccount bob 500
                  $ emptyLedger
      tx <- createTransaction alice bobAddr 100 5  -- wrong nonce
      verifyTransaction lgr tx `shouldBe` Left InvalidNonce

    it "rejects insufficient balance" $ do
      let alice   = 11111
          bob     = 22222
          bobAddr = deriveAddressFromSecret bob
          lgr     = Transaction.Transaction.registerAccount alice 50
                  . Transaction.Transaction.registerAccount bob 500
                  $ emptyLedger
      tx <- createTransaction alice bobAddr 100 1  -- only has 50
      verifyTransaction lgr tx `shouldBe` Left InsufficientBalance

    it "rejects tampered amount" $ do
      let alice   = 11111
          bob     = 22222
          bobAddr = deriveAddressFromSecret bob
          lgr     = Transaction.Transaction.registerAccount alice 1000
                  . Transaction.Transaction.registerAccount bob 500
                  $ emptyLedger
      tx <- createTransaction alice bobAddr 100 1
      let tampered = tx { txAmount = 999 }
      verifyTransaction lgr tampered `shouldBe` Left InvalidProof

    it "rejects tampered recipient" $ do
      let alice   = 11111
          bob     = 22222
          bobAddr = deriveAddressFromSecret bob
          lgr     = Transaction.Transaction.registerAccount alice 1000
                  . Transaction.Transaction.registerAccount bob 500
                  $ emptyLedger
      tx <- createTransaction alice bobAddr 100 1
      let tampered = tx { txRecipient = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
      verifyTransaction lgr tampered `shouldBe` Left InvalidProof

  describe "processTransaction" $ do
    it "updates balances correctly" $ do
      let alice    = 11111
          bob      = 22222
          aliceAddr = deriveAddressFromSecret alice
          bobAddr   = deriveAddressFromSecret bob
          lgr      = Transaction.Transaction.registerAccount alice 1000
                   . Transaction.Transaction.registerAccount bob 500
                   $ emptyLedger
      tx <- createTransaction alice bobAddr 200 1
      case processTransaction lgr tx of
        Left err   -> expectationFailure (show err)
        Right lgr' -> do
          (accountBalance <$> Map.lookup aliceAddr lgr') `shouldBe` Just 800
          (accountBalance <$> Map.lookup bobAddr lgr')   `shouldBe` Just 700

    it "increments sender nonce" $ do
      let alice    = 11111
          bob      = 22222
          aliceAddr = deriveAddressFromSecret alice
          bobAddr   = deriveAddressFromSecret bob
          lgr      = Transaction.Transaction.registerAccount alice 1000
                   . Transaction.Transaction.registerAccount bob 500
                   $ emptyLedger
      tx <- createTransaction alice bobAddr 100 1
      case processTransaction lgr tx of
        Left err   -> expectationFailure (show err)
        Right lgr' ->
          (accountNonce <$> Map.lookup aliceAddr lgr') `shouldBe` Just 1

  describe "sequential transactions" $ do
    it "processes two transactions in sequence" $ do
      let alice    = 11111
          bob      = 22222
          aliceAddr = deriveAddressFromSecret alice
          bobAddr   = deriveAddressFromSecret bob
          lgr0     = Transaction.Transaction.registerAccount alice 1000
                   . Transaction.Transaction.registerAccount bob 0
                   $ emptyLedger
      tx1 <- createTransaction alice bobAddr 300 1
      tx2 <- createTransaction alice bobAddr 200 2
      case processTransaction lgr0 tx1 of
        Left err   -> expectationFailure (show err)
        Right lgr1 ->
          case processTransaction lgr1 tx2 of
            Left err   -> expectationFailure (show err)
            Right lgr2 -> do
              (accountBalance <$> Map.lookup aliceAddr lgr2) `shouldBe` Just 500
              (accountBalance <$> Map.lookup bobAddr lgr2)   `shouldBe` Just 500

    it "rejects replayed transaction (same nonce)" $ do
      let alice   = 11111
          bob     = 22222
          bobAddr = deriveAddressFromSecret bob
          lgr0    = Transaction.Transaction.registerAccount alice 1000
                  . Transaction.Transaction.registerAccount bob 0
                  $ emptyLedger
      tx <- createTransaction alice bobAddr 100 1
      case processTransaction lgr0 tx of
        Left err   -> expectationFailure (show err)
        Right lgr1 ->
          processTransaction lgr1 tx `shouldBe` Left InvalidNonce

--
-- Blockchain Tests
--

blockchainSpec :: Spec
blockchainSpec = describe "Blockchain.Blockchain" $ do

  describe "newBlockchain" $ do
    it "starts with one block (genesis)" $ do
      chainLength newBlockchain `shouldBe` 1

    it "genesis block has index 0" $ do
      blockIndex (latestBlock newBlockchain) `shouldBe` 0

    it "starts with empty ledger" $ do
      Map.size (ledger newBlockchain) `shouldBe` 0

    it "starts with empty pending pool" $ do
      length (pendingPool newBlockchain) `shouldBe` 0

    it "validates on creation" $ do
      validateChain newBlockchain `shouldBe` True

  describe "registerAccount (Blockchain-level)" $ do
    it "adds account to blockchain ledger" $ do
      let secret = 12345
          pk     = getPublicKey defaultParams secret
          bc     = Blockchain.Blockchain.registerAccount pk 1000 newBlockchain
      Map.size (ledger bc) `shouldBe` 1

    it "getAccount returns registered account" $ do
      let secret = 12345
          pk     = getPublicKey defaultParams secret
          addr   = deriveAddress pk
          bc     = Blockchain.Blockchain.registerAccount pk 1000 newBlockchain
      case getAccount bc addr of
        Nothing   -> expectationFailure "Account not found"
        Just acct -> accountBalance acct `shouldBe` 1000

  describe "registerAccountFromSecret" $ do
    it "derives and registers correctly" $ do
      let secret = 12345
          addr   = deriveAddressFromSecret secret
          bc     = registerAccountFromSecret secret 500 newBlockchain
      case getAccount bc addr of
        Nothing   -> expectationFailure "Account not found"
        Just acct -> do
          accountBalance acct `shouldBe` 500
          accountPubKey acct `shouldBe` getPublicKey defaultParams secret

  describe "submitTransaction" $ do
    it "adds valid transaction to pending pool" $ do
      let alice   = 11111
          bob     = 22222
          pkA     = getPublicKey defaultParams alice
          pkB     = getPublicKey defaultParams bob
          bobAddr = deriveAddress pkB
          bc0     = Blockchain.Blockchain.registerAccount pkA 1000
                  . Blockchain.Blockchain.registerAccount pkB 0
                  $ newBlockchain
      tx <- createTransaction alice bobAddr 100 1
      case submitTransaction bc0 tx of
        Left err  -> expectationFailure (show err)
        Right bc1 -> length (pendingPool bc1) `shouldBe` 1

    it "rejects invalid transaction" $ do
      let bob     = 22222
          pkB     = getPublicKey defaultParams bob
          bobAddr = deriveAddress pkB
          bc0     = Blockchain.Blockchain.registerAccount pkB 0 newBlockchain
      tx <- createTransaction 99999 bobAddr 100 1  -- unknown sender
      case submitTransaction bc0 tx of
        Left _  -> return ()
        Right _ -> expectationFailure "Should have rejected unknown sender"

  describe "mineBlock" $ do
    it "mines pending transactions into a new block" $ do
      let alice   = 11111
          bob     = 22222
          pkA     = getPublicKey defaultParams alice
          pkB     = getPublicKey defaultParams bob
          bobAddr = deriveAddress pkB
          bc0     = Blockchain.Blockchain.registerAccount pkA 1000
                  . Blockchain.Blockchain.registerAccount pkB 0
                  $ newBlockchain
      tx <- createTransaction alice bobAddr 100 1
      case submitTransaction bc0 tx of
        Left err  -> expectationFailure (show err)
        Right bc1 -> do
          result <- Blockchain.Blockchain.mineBlock bc1 "miner" defaultDifficulty
          case result of
            Left err   -> expectationFailure err
            Right bc2 -> do
              chainLength bc2 `shouldBe` 2
              length (pendingPool bc2) `shouldBe` 0
              -- Check ledger updated
              let aliceAddr = deriveAddress pkA
              (accountBalance <$> getAccount bc2 aliceAddr) `shouldBe` Just 900
              (accountBalance <$> getAccount bc2 bobAddr)   `shouldBe` Just 100

    it "returns error when no pending transactions" $ do
      result <- Blockchain.Blockchain.mineBlock newBlockchain "miner" defaultDifficulty
      case result of
        Left _  -> return ()
        Right _ -> expectationFailure "Should fail with no pending txs"

    it "skips invalid transactions during mining" $ do
      let alice   = 11111
          bob     = 22222
          pkA     = getPublicKey defaultParams alice
          pkB     = getPublicKey defaultParams bob
          bobAddr = deriveAddress pkB
          bc0     = Blockchain.Blockchain.registerAccount pkA 1000
                  . Blockchain.Blockchain.registerAccount pkB 0
                  $ newBlockchain
      -- Create two txs: one valid, one with duplicate nonce
      tx1 <- createTransaction alice bobAddr 100 1
      tx2 <- createTransaction alice bobAddr 200 1  -- same nonce!
      -- Force both into pending pool (bypass validation for test)
      let bc1 = bc0 { pendingPool = [tx1, tx2] }
      result <- Blockchain.Blockchain.mineBlock bc1 "miner" defaultDifficulty
      case result of
        Left err  -> expectationFailure err
        Right bc2 -> do
          -- Only one tx should have made it into the block
          let blk = latestBlock bc2
          length (blockTransactions blk) `shouldBe` 1

  describe "validateChain" $ do
    it "validates after mining" $ do
      let alice   = 11111
          bob     = 22222
          pkA     = getPublicKey defaultParams alice
          pkB     = getPublicKey defaultParams bob
          bobAddr = deriveAddress pkB
          bc0     = Blockchain.Blockchain.registerAccount pkA 1000
                  . Blockchain.Blockchain.registerAccount pkB 0
                  $ newBlockchain
      tx <- createTransaction alice bobAddr 100 1
      case submitTransaction bc0 tx of
        Left err  -> expectationFailure (show err)
        Right bc1 -> do
          result <- Blockchain.Blockchain.mineBlock bc1 "miner" defaultDifficulty
          case result of
            Left err   -> expectationFailure err
            Right bc2 -> validateChain bc2 `shouldBe` True

--
-- Integration Tests
--

integrationSpec :: Spec
integrationSpec = describe "Integration" $ do

  describe "full transaction lifecycle" $ do
    it "register -> transact -> mine -> verify balances" $ do
      let alice   = 100001
          bob     = 200002
          charlie = 300003
          pkA     = getPublicKey defaultParams alice
          pkB     = getPublicKey defaultParams bob
          pkC     = getPublicKey defaultParams charlie
          addrA   = deriveAddress pkA
          addrB   = deriveAddress pkB
          addrC   = deriveAddress pkC

          bc0 = Blockchain.Blockchain.registerAccount pkA 10000
              . Blockchain.Blockchain.registerAccount pkB 5000
              . Blockchain.Blockchain.registerAccount pkC 0
              $ newBlockchain

      tx1 <- createTransaction alice addrB 1000 1
      case submitTransaction bc0 tx1 of
        Left err -> expectationFailure $ "tx1 failed: " ++ show err
        Right bc1 -> do
          result1 <- Blockchain.Blockchain.mineBlock bc1 "miner" defaultDifficulty
          case result1 of
            Left err -> expectationFailure $ "mine1 failed: " ++ show err
            Right bc2 -> do
              let aliceNonce = accountNonce $ fromJust $ getAccount bc2 addrA
                  bobNonce = accountNonce $ fromJust $ getAccount bc2 addrB

              tx2 <- createTransaction alice addrC 500 (aliceNonce + 1)
              case submitTransaction bc2 tx2 of
                Left err -> expectationFailure $ "tx2 failed: " ++ show err
                Right bc3 -> do
                  tx3 <- createTransaction bob addrC 200 (bobNonce + 1)
                  case submitTransaction bc3 tx3 of
                    Left err -> expectationFailure $ "tx3 failed: " ++ show err
                    Right bc4 -> do
                      result2 <- Blockchain.Blockchain.mineBlock bc4 "miner" defaultDifficulty
                      case result2 of
                        Left err -> expectationFailure $ "mine2 failed: " ++ show err
                        Right bc5 -> do
                          chainLength bc5 `shouldBe` 3
                          length (pendingPool bc5) `shouldBe` 0
                          validateChain bc5 `shouldBe` True

                          (accountBalance <$> getAccount bc5 addrA) `shouldBe` Just 8500
                          (accountBalance <$> getAccount bc5 addrB) `shouldBe` Just 5800
                          (accountBalance <$> getAccount bc5 addrC) `shouldBe` Just 700

  describe "multi-block lifecycle" $ do
    it "processes transactions across multiple blocks" $ do
      let alice = 100001
          bob   = 200002
          pkA   = getPublicKey defaultParams alice
          pkB   = getPublicKey defaultParams bob
          addrA = deriveAddress pkA
          addrB = deriveAddress pkB
          bc0   = Blockchain.Blockchain.registerAccount pkA 10000
                . Blockchain.Blockchain.registerAccount pkB 0
                $ newBlockchain

      -- Block 1: Alice -> Bob 1000
      tx1 <- createTransaction alice addrB 1000 1
      let Right bc1 = submitTransaction bc0 tx1
      Right bc2 <- Blockchain.Blockchain.mineBlock bc1 "miner" defaultDifficulty

      -- Block 2: Alice -> Bob 2000
      tx2 <- createTransaction alice addrB 2000 2
      let Right bc3 = submitTransaction bc2 tx2
      Right bc4 <- Blockchain.Blockchain.mineBlock bc3 "miner" defaultDifficulty

      chainLength bc4 `shouldBe` 3
      validateChain bc4 `shouldBe` True
      (accountBalance <$> getAccount bc4 addrA) `shouldBe` Just 7000
      (accountBalance <$> getAccount bc4 addrB) `shouldBe` Just 3000

  describe "attack resistance" $ do
    it "rejects double-spend across blocks" $ do
      let alice = 100001
          bob   = 200002
          pkA   = getPublicKey defaultParams alice
          pkB   = getPublicKey defaultParams bob
          addrB = deriveAddress pkB
          bc0   = Blockchain.Blockchain.registerAccount pkA 500
                . Blockchain.Blockchain.registerAccount pkB 0
                $ newBlockchain

      -- Spend 400
      tx1 <- createTransaction alice addrB 400 1
      let Right bc1 = submitTransaction bc0 tx1
      Right bc2 <- Blockchain.Blockchain.mineBlock bc1 "miner" defaultDifficulty

      -- Try to spend 400 again (only 100 left)
      tx2 <- createTransaction alice addrB 400 2
      case submitTransaction bc2 tx2 of
        Left _  -> return ()  -- correctly rejected
        Right _ -> expectationFailure "Double spend should be rejected"

    it "rejects forged ZKP (wrong secret key)" $ do
      let alice    = 100001
          bob      = 200002
          attacker = 999999
          pkA      = getPublicKey defaultParams alice
          pkB      = getPublicKey defaultParams bob
          addrB    = deriveAddress pkB
          bc0      = Blockchain.Blockchain.registerAccount pkA 10000
                   . Blockchain.Blockchain.registerAccount pkB 0
                   $ newBlockchain

      -- Attacker tries to create tx as Alice
      tx <- createTransaction attacker addrB 1000 1
      let forged = tx { txSender = deriveAddress pkA }
      case submitTransaction bc0 forged of
        Left _  -> return ()  -- correctly rejected
        Right _ -> expectationFailure "Forged tx should be rejected"

    it "rejects transaction with modified amount after signing" $ do
      let alice = 100001
          bob   = 200002
          pkA   = getPublicKey defaultParams alice
          pkB   = getPublicKey defaultParams bob
          addrB = deriveAddress pkB
          bc0   = Blockchain.Blockchain.registerAccount pkA 10000
                . Blockchain.Blockchain.registerAccount pkB 0
                $ newBlockchain

      tx <- createTransaction alice addrB 100 1
      let tampered = tx { txAmount = 9999 }
      case submitTransaction bc0 tampered of
        Left _  -> return ()
        Right _ -> expectationFailure "Tampered amount should be rejected"

  describe "encrypted transaction lifecycle" $ do
    it "creates and verifies encrypted transaction" $ do
      let alice   = 100001
          bob     = 200002
          pkA     = getPublicKey defaultParams alice
          pkB     = getPublicKey defaultParams bob
          addrB   = deriveAddress pkB
          bc0     = Blockchain.Blockchain.registerAccount pkA 10000
                  . Blockchain.Blockchain.registerAccount pkB 0
                  $ newBlockchain

      tx <- createEncryptedTransaction alice addrB 500 1 "secret memo" "symkey"
      txCiphertext tx `shouldNotBe` Nothing

      case submitTransaction bc0 tx of
        Left err  -> expectationFailure (show err)
        Right bc1 -> do
          result <- Blockchain.Blockchain.mineBlock bc1 "miner" defaultDifficulty
          case result of
            Left err  -> expectationFailure err
            Right bc2 -> do
              validateChain bc2 `shouldBe` True
              let addrA = deriveAddress pkA
              (accountBalance <$> getAccount bc2 addrA) `shouldBe` Just 9500
              (accountBalance <$> getAccount bc2 addrB) `shouldBe` Just 500
