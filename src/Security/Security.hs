module Security.Security where

import ZKP.ZKP
import Security.HomomorphicEncryption

-- Function to create a private transaction
createPrivateTransaction :: String -> ZKP
createPrivateTransaction transaction = 
  let 
    zkp = createZKP transaction "proof"
  in 
    zkp

-- Function to verify a private transaction
verifyPrivateTransaction :: ZKP -> Bool
verifyPrivateTransaction zkp = verifyZKP zkp

-- Function to create an encrypted transaction
createEncryptedTransaction :: String -> String -> (ZKP, EncryptedData)
createEncryptedTransaction transaction key = 
  let zkp = generateZKProof transaction key
      encrypted = encryptData transaction key
  in (zkp, encrypted)

-- Function to verify and decrypt a transaction
verifyAndDecrypt :: ZKP -> String -> EncryptedData -> Maybe String
verifyAndDecrypt zkp key encryptedData = 
  if verifyZKP zkp
    then Just (decryptData key encryptedData)
    else Nothing
