{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}

module Transaction.Transaction where

import ZKP.ZKP
import Cryptography.HomomorphicEncryption
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString as B
import qualified Crypto.Hash as H
import Data.ByteArray              (convert)
import Crypto.Number.Serialize     (os2ip)
import qualified Data.Map.Strict as Map
import Data.Map.Strict             (Map)
import Data.Aeson                  (ToJSON, FromJSON)
import GHC.Generics                (Generic)
import Numeric                     (showHex)

--
-- Addresses  (derived from public key — like Bitcoin/Ethereum)
--

type Address = String

-- address = first 40 hex chars of SHA-256(hex(publicKey))
deriveAddress :: Integer -> Address
deriveAddress pubKey =
  let pubKeyBS = BC.pack (showHex pubKey "")
      digest   = H.hash pubKeyBS :: H.Digest H.SHA256
      digestBS = convert digest  :: B.ByteString
  in take 40 (showHex (os2ip digestBS) "")

-- Convenience: secret key -> address
deriveAddressFromSecret :: Integer -> Address
deriveAddressFromSecret =
  deriveAddress . getPublicKey defaultParams

--
-- Ledger  (on-chain state)
--

data AccountState = AccountState
  { accountPubKey  :: !Integer   -- Schnorr public key  y = g^x mod p
  , accountBalance :: !Integer
  , accountNonce   :: !Integer   -- Monotonic, prevents replay
  } deriving (Show, Eq, Generic)

instance ToJSON AccountState
instance FromJSON AccountState

type Ledger = Map Address AccountState

emptyLedger :: Ledger
emptyLedger = Map.empty

-- Register a new account (eg. genesis or first deposit)
registerAccount :: Integer   -- Secret key  (known only to owner)
                -> Integer   -- Initial balance
                -> Ledger -> Ledger
registerAccount secret balance ledger =
  let pubKey  = getPublicKey defaultParams secret
      addr    = deriveAddress pubKey
      account = AccountState
        { accountPubKey  = pubKey
        , accountBalance = balance
        , accountNonce   = 0
        }
  in Map.insert addr account ledger

lookupPublicKey :: Ledger -> Address -> Maybe Integer
lookupPublicKey ledger addr = accountPubKey <$> Map.lookup addr ledger

-- Register with a public key directly (production - client never sends secret key)
registerAccountWithPK :: Integer    -- ^ Public key
                      -> Integer    -- ^ Initial balance
                      -> Ledger -> Ledger
registerAccountWithPK pubKey balance lgr =
  let addr    = deriveAddress pubKey
      account = AccountState
        { accountPubKey  = pubKey
        , accountBalance = balance
        , accountNonce   = 0
        }
  in Map.insert addr account lgr

--
-- Transaction
--

data BlockchainTx = BlockchainTx
  { txSender     :: !Address
  , txRecipient  :: !Address
  , txAmount     :: !Integer
  , txNonce      :: !Integer               -- Must be previous nonce + 1
  , txCiphertext :: !(Maybe EncryptedData) -- Optional encrypted memo / payload
  , txProof      :: !ZKP                   -- Schnorr ZKP over canonical payload
  } deriving (Show, Eq, Generic)

instance ToJSON BlockchainTx
instance FromJSON BlockchainTx

-- Canonical byte representation of everything except the proof
--   This is what the prover binds the ZKP to, and what the verifier reconstructs independently
--   Uses domain-separated, delimited fields to prevent ambiguity
canonicalPayload :: Address
                 -> Address
                 -> Integer
                 -> Integer
                 -> Maybe EncryptedData
                 -> B.ByteString
canonicalPayload sender recipient amount nonce mCipher =
  BC.pack $ concat
    [ "tx|sender:"    , sender
    , "|recipient:"   , recipient
    , "|amount:"      , show amount
    , "|nonce:"       , show nonce
    , "|data:"        , maybe "" show mCipher
    ]

-- Reconstruct the payload from an existing transaction (for verification)
txCanonicalPayload :: BlockchainTx -> B.ByteString
txCanonicalPayload tx =
  canonicalPayload
    (txSender tx) (txRecipient tx)
    (txAmount tx) (txNonce tx)
    (txCiphertext tx)

--
-- Transaction creation  (runs on the sender's machine)
--

-- Create a plain (unencrypted) transaction
createTransaction :: Integer   -- ^ Sender's secret key
                  -> Address   -- ^ Recipient address
                  -> Integer   -- ^ Amount
                  -> Integer   -- ^ Nonce
                  -> IO BlockchainTx
createTransaction secret recipient amount nonce =
  createTransactionWith secret recipient amount nonce Nothing

-- Create a transaction with an encrypted payload
createEncryptedTransaction :: Integer   -- Sender's secret key
                           -> Address   -- Recipient address
                           -> Integer   -- Amount
                           -> Integer   -- Nonce
                           -> String    -- Plaintext memo
                           -> String    -- Symmetric encryption key
                           -> IO BlockchainTx
createEncryptedTransaction secret recipient amount nonce plaintext encKey =
  createTransactionWith secret recipient amount nonce
    (Just (plaintext, encKey))

-- Internal: build, sign, and package a transaction
createTransactionWith :: Integer
                      -> Address
                      -> Integer
                      -> Integer
                      -> Maybe (String, String)   -- (plaintext, encKey)
                      -> IO BlockchainTx
createTransactionWith secret recipient amount nonce mEncrypt = do
  let params  = defaultParams
      pubKey  = getPublicKey params secret
      sender  = deriveAddress pubKey
      mCipher = case mEncrypt of
                  Just (pt, ek) -> Just (encryptData pt ek)
                  Nothing       -> Nothing
      payload = canonicalPayload sender recipient amount nonce mCipher

  proof <- generateZKProofIO params secret payload

  return BlockchainTx
    { txSender     = sender
    , txRecipient  = recipient
    , txAmount     = amount
    , txNonce      = nonce
    , txCiphertext = mCipher
    , txProof      = proof
    }

--
-- Transaction verification  (runs on every validator node)
--

data TxValidationError
  = UnknownSender          -- Address not in ledger
  | AddressMismatch        -- Stored pubkey doesn't hash to sender address
  | InvalidNonce           -- Nonce != expected (replay or ordering)
  | InsufficientBalance    -- Sender can't cover the amount
  | InvalidProof           -- ZKP verification failed
  deriving (Show, Eq)

-- Full transaction validation.
--
--   1. Resolve sender address => public key  (from ledger)
--   2. Confirm the address is correctly derived from that key
--   3. Check the nonce  (replay protection)
--   4. Check the balance
--   5. Verify the Schnorr ZKP against the reconstructed payload
verifyTransaction :: Ledger -> BlockchainTx -> Either TxValidationError ()
verifyTransaction ledger tx = do
  -- 1. Sender must exist
  account <- maybe (Left UnknownSender) Right
               (Map.lookup (txSender tx) ledger)

  let pubKey = accountPubKey account

  -- 2. Address <=> public key consistency
  if deriveAddress pubKey /= txSender tx
    then Left AddressMismatch
    else Right ()

  -- 3. Nonce must be exactly previous + 1
  if txNonce tx /= accountNonce account + 1
    then Left InvalidNonce
    else Right ()

  -- 4. Sufficient funds
  if txAmount tx > accountBalance account
    then Left InsufficientBalance
    else Right ()

  -- 5. Cryptographic proof
  --    Reconstruct the canonical payload from the tx fields
  --    (never trust the prover's payload; rebuild it)
  let payload = txCanonicalPayload tx
  if not (verifyZKPWithKey defaultParams (txProof tx) pubKey payload)
    then Left InvalidProof
    else Right ()

--
-- Ledger updates  (after successful verification)
--

-- Apply a verified transaction to the ledger, updating balances and nonces for both sender and recipient
applyTransaction :: Ledger -> BlockchainTx -> Ledger
applyTransaction ledger tx =
    creditRecipient . debitSender $ ledger
  where
    debitSender = Map.adjust
      (\a -> a { accountBalance = accountBalance a - txAmount tx
               , accountNonce   = accountNonce a + 1
               })
      (txSender tx)

    creditRecipient = Map.adjust
      (\a -> a { accountBalance = accountBalance a + txAmount tx })
      (txRecipient tx)

-- Validate then apply.  Returns the updated ledger or an error
processTransaction :: Ledger -> BlockchainTx -> Either TxValidationError Ledger
processTransaction ledger tx = do
  verifyTransaction ledger tx
  return (applyTransaction ledger tx)

processTransactionWithoutNonce :: Ledger -> BlockchainTx -> Either TxValidationError Ledger
processTransactionWithoutNonce ledger tx = do
  verifyTransactionWithoutNonce ledger tx
  return (applyTransaction ledger tx)

-- Verify a transaction, then decrypt its ciphertext if present
verifyAndDecrypt :: Ledger
                 -> BlockchainTx
                 -> String               -- Symmetric decryption key
                 -> Either TxValidationError (Maybe String)
verifyAndDecrypt ledger tx decKey = do
  verifyTransaction ledger tx
  case txCiphertext tx of
    Nothing     -> Right Nothing
    Just cipher -> Right (Just (decryptData decKey cipher))

verifyTransactionWithoutNonce :: Ledger -> BlockchainTx -> Either TxValidationError ()
verifyTransactionWithoutNonce ledger tx = do
  account <- maybe (Left UnknownSender) Right
               (Map.lookup (txSender tx) ledger)

  let pubKey = accountPubKey account

  if deriveAddress pubKey /= txSender tx
    then Left AddressMismatch
    else Right ()

  if txAmount tx > accountBalance account
    then Left InsufficientBalance
    else Right ()

  let payload = txCanonicalPayload tx
  if not (verifyZKPWithKey defaultParams (txProof tx) pubKey payload)
    then Left InvalidProof
    else Right ()