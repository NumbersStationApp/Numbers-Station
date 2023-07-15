func sendMessage( chatText: String) -> Bool {
        
    if chatText == "" {
        return false
    }
    
    let backgroundUploadID = UIApplication.shared.beginBackgroundTask {
        print("send message task about to be killed!")
    }
    
    let toId = GlobalMMVM.conversations[GlobalMMVM.selectedConversationId].otherParticipantId
    guard let fromId = FirebaseManager.shared.auth.currentUser?.uid else { return false }
    let unencryptedMessageToSend: Data = chatText.data(using: .utf8) ?? Data()
    let length = unencryptedMessageToSend.count
    var OTPEncryptedMessageToSend: Data = Data(count: length)
    let ephemeralKeyForSendingNextMessageToUs: Curve25519.KeyAgreement.PrivateKey = Curve25519.KeyAgreement.PrivateKey()
    let ephemeralKeyForSendingNextMessageToUs2: Curve25519.KeyAgreement.PrivateKey = Curve25519.KeyAgreement.PrivateKey()
    var ephemeralKeysForSendingFutureMessagesToUsWasSaved: Bool = false
    var ephemeralKeysForSendingFutureMessagesToUsWasSaved2: Bool = false
    let keyNumber: Int64 = Int64.random(in: 4...Int64.max)
    let keyNumber2: Int64 = Int64.random(in: 4...Int64.max)
    
    if GlobalMMVM.subscriptionActive == false {
        
        GlobalMMVM.conversations[GlobalMMVM.selectedConversationId].messagesinConversation.append(.init(documentId: UUID().uuidString, timeSentTimestamp: Timestamp(date: Date()), timeExpiresTimestamp: Timestamp(date: Date() + 90), clearText: "Error: unable to send message, without an active subscription you can only receive messages. Go to app settings to activate a subscription.", messageType: Constants.messageTypeError, fromId: fromId))
        
        GlobalMMVM.forceRefresh += 1
        UIApplication.shared.endBackgroundTask(backgroundUploadID)
        return false
    }
    
    let document = FirebaseManager.shared.firestore
        .collection("messages")
        .document(toId)
        .collection("messages")

    // get the recipient's latest ephemereal key, if none present then daily key, if not present then long term default key agreement key...
    let result = getUserPublicDefaultDailyEphemeralKeyAgreementKey(userUid: toId)
    if result.successful == true {
        var readOffset: UInt64 = 0
        var fileNumber: UInt64 = 0
  
        var foundInAddressBookAndUsingOTP: Bool = false
        
        // is this conversation OTP encrypted or not?
        if GlobalMMVM.conversations[GlobalMMVM.selectedConversationId].conversationTypeIsOTP == true {
            for (addressbook_index, address) in GlobalMMVM.addressbook.enumerated() {
                if address.FirestoreUid == toId {
                    if address.OTPsToEncrypt.count > 0  {
    
                        do {
                            var fileOTPURL: URL = globalAppSupportPath.appendingPathComponent(getSHA512HashForFileName(stringToHash: fromId)).appendingPathComponent("OTPs").appendingPathComponent(String(address.OTPsToEncrypt[0])).appendingPathExtension("nsotp")
                            
                            var file: FileHandle? = try FileHandle(forUpdating: fileOTPURL)
                            var EOFOffset: UInt64 = try file?.seekToEnd() ?? 0
                            
                            if EOFOffset >= length {
                                fileNumber = address.OTPsToEncrypt[0]
                                // we're good! continue on
                            }
                            else {
                                // sending OTP isn't large enough...cannot send message
                                // so first close and delete the used up file
                                try file?.close()
                                
                                let fileManager = FileManager.default
                                // Check if file exists
                                if fileManager.fileExists(atPath: fileOTPURL.path) {
                                    // Delete file
                                    try fileManager.removeItem(at: fileOTPURL )
                                } else {
                                    print("File does not exist")
                                }
                     
                                // now remove the reference
                                GlobalMMVM.addressbook[addressbook_index].OTPsToEncrypt.remove(at:0)
                            }
                            
                            if fileNumber != 0 {
                                readOffset = EOFOffset - UInt64(length)
                                try file?.seek(toOffset: readOffset)
                                let OTP = try file?.read(upToCount: length)
                                
                                // overwrite the part of the pad we used, then truncate the file, really no point though in writing
                                // to portion used for OTP due to way SSD storage works and "leftovers" are AES-256 encrypted anyway
                                // and now orphaned from the AES key used and will be re-used/overwritten by the operating system
                                let randomOverwriteData: Data = randomData(length: length)  // source is TRNG
                                try file?.write(contentsOf: randomOverwriteData)
                                try file?.truncate(atOffset: readOffset)
                                try file?.synchronize()
                                try file?.close()
                                
                                if( length == OTP?.count ) {
                                    for i in 0..<length {
                                        //let a = unencryptedMessageToSend[i]
                                        //let b = OTP?[i] ?? 0b00000000
                                        //let c = a ^ b
                                        OTPEncryptedMessageToSend[i] = unencryptedMessageToSend[i] ^ (OTP?[i] ?? 0b00000000)
                                    }
                                }
                    
                                foundInAddressBookAndUsingOTP = true
                            }
                        } catch {
                            print(error)
                        }
                    }
                    
                    if fileNumber == 0 {
                        GlobalMMVM.conversations[GlobalMMVM.selectedConversationId].messagesinConversation.append(.init(documentId: UUID().uuidString, timeSentTimestamp: Timestamp(date: Date()), timeExpiresTimestamp: Timestamp(date: Date() + 90), clearText: "Error: zero or insufficient OTP material remaining to send message, exchange additional material with recipient or use non-OTP type conversation.", messageType: Constants.messageTypeError, fromId: fromId))
                        
                        GlobalMMVM.forceRefresh += 1
                        UIApplication.shared.endBackgroundTask(backgroundUploadID)
                        return false
                    }
                
                    break
                }
            }
        }
        
        if GlobalMMVM.conversations[GlobalMMVM.selectedConversationId].conversationTypeIsOTP == true &&
            foundInAddressBookAndUsingOTP == false {
            
            // we have a problem...OTP failed for some reason so don't continue!
  
            GlobalMMVM.conversations[GlobalMMVM.selectedConversationId].messagesinConversation.append(.init(documentId: UUID().uuidString, timeSentTimestamp: Timestamp(date: Date()), timeExpiresTimestamp: Timestamp(date: Date() + 90), clearText: "Error: OTP encryption error, unable to send message.", messageType: Constants.messageTypeError, fromId: fromId))
            
            GlobalMMVM.forceRefresh += 1
            UIApplication.shared.endBackgroundTask(backgroundUploadID)
            return false
        }
        
        ephemeralKeysForSendingFutureMessagesToUsWasSaved = addEphemeralPrivateKeyToReceivingChain(userUid: toId, newKeyAsData: ephemeralKeyForSendingNextMessageToUs.rawRepresentation, keyNumber: keyNumber)
        ephemeralKeysForSendingFutureMessagesToUsWasSaved2 = addEphemeralPrivateKeyToReceivingChain(userUid: toId, newKeyAsData: ephemeralKeyForSendingNextMessageToUs2.rawRepresentation, keyNumber: keyNumber2)

        // now need to encode parts of message that should be encrypted (not for OTP encryption but standard middle layer of encryption)
        var dataEncodedForEncryption: Data = Data()
        let encoder = PropertyListEncoder()
        let dataPayload: DataPayload = DataPayload(
            messageType: foundInAddressBookAndUsingOTP ? Constants.messageTypeTextWithOTP : Constants.messageTypeText,
            locationInPad: readOffset,
            fileNumber: fileNumber,
            message: foundInAddressBookAndUsingOTP ? OTPEncryptedMessageToSend : unencryptedMessageToSend,
            ephemeralKey: ephemeralKeysForSendingFutureMessagesToUsWasSaved ? ephemeralKeyForSendingNextMessageToUs.publicKey.rawRepresentation : Data(),
            ephemeralKey2: ephemeralKeysForSendingFutureMessagesToUsWasSaved2 ? ephemeralKeyForSendingNextMessageToUs2.publicKey.rawRepresentation : Data(),
            fromId: fromId,
            ephemeralKeyNumber: ephemeralKeysForSendingFutureMessagesToUsWasSaved ? keyNumber : 0,
            ephemeralKeyNumber2: ephemeralKeysForSendingFutureMessagesToUsWasSaved2 ? keyNumber2 : 0 )
        
        do {
            let encodedData = try encoder.encode(dataPayload)
            dataEncodedForEncryption = try (encodedData as NSData).compressed(using: .zlib) as Data
            
        } catch {
            print("encoding or compression failed")
            UIApplication.shared.endBackgroundTask(backgroundUploadID)
            return false
        }
        
        var sealedEncryptedBoxToSend: Data =  Data()
        let salt = randomData(length: 32) // source is TRNG
        
        // now that we have OTP sorted out...need to sort out regular encryption

        // create a new ephemeral key for sender
        let senderPrivateKey = Curve25519.KeyAgreement.PrivateKey()
       
        do {
            // using the recipient's most recent ephemeral key, daily key or default long term key
            // contained in result.recipientPublickeyAsData, create a shared secret and AES-256 key with senders ephemeral key
            let recipientPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: result.recipientPublickeyAsData)
            let ourSharedSecretSenderSide = try senderPrivateKey.sharedSecretFromKeyAgreement(with: recipientPublicKey)
            let ourSymmetricKeySenderSide = ourSharedSecretSenderSide.hkdfDerivedSymmetricKey(using: SHA512.self, salt: salt, sharedInfo: Data(), outputByteCount: 32)
            sealedEncryptedBoxToSend = try AES.GCM.seal( dataEncodedForEncryption, using: ourSymmetricKeySenderSide).combined ?? Data()
          
        } catch {
            print(error.localizedDescription)
        }

         /*
          settingsExpireAtSelection
              "3 Hours" = 1
              "6 Hours" = 2
              "12 Hours" = 3
              "1 Day" = 4
              "2 Days" = 5
              "3 Days" = 6 (the default)
              "4 Days" = 7
              "5 Days" = 8
              "6 Days" = 9
              "7 Days" = 10
        */
        
        var expiryDuration = UserDefaults.standard.float(forKey: "settingsExpireAtSelection")
        if expiryDuration < 1 || expiryDuration > 10 {
            expiryDuration = 6 // set the default if an incorrect value is returned
        }
        
        var hoursToExpiry: TimeInterval = 72
        if expiryDuration == 1 { hoursToExpiry = 3 }
        else if expiryDuration == 2 { hoursToExpiry = 6 }
        else if expiryDuration == 3 { hoursToExpiry = 12 }
        else if expiryDuration == 4 { hoursToExpiry = 24 }
        else if expiryDuration == 5 { hoursToExpiry = 48 }
        else if expiryDuration == 6 { hoursToExpiry = 72 }
        else if expiryDuration == 7 { hoursToExpiry = 96 }
        else if expiryDuration == 8 { hoursToExpiry = 120 }
        else if expiryDuration == 9 { hoursToExpiry = 144 }
        else if expiryDuration == 10 { hoursToExpiry = 168 }

        let expireAt: Date = Date() + (3600 /* # of seconds in an hour */ * hoursToExpiry)
        
        let digest512 = SHA512.hash(data: sealedEncryptedBoxToSend)
        let signatureOfDigestForEncryptedPayload = try! GlobalMMVM.userPrivateSigningKeyP256.signature(for: Data(digest512)).rawRepresentation

        let toIdHashed = Data(SHA512.hash(data: toId.data(using: .utf8) ?? Data())).hexEncodedString()
        
        let documentDataToSendToServer = [
            // first 8 characters of toId for notification
            Constants.toId: toIdHashed.prefix(8),
            // encrypted
            Constants.encryptedPayload: sealedEncryptedBoxToSend,
            // unencrypted
            Constants.FCM: getUserFCMToken(userUid: toId),
            Constants.messageVersion: "1",
            Constants.expireAt: Timestamp(date: expireAt),
            //Constants.fromId: fromId,
            Constants.timestamp: FieldValue.serverTimestamp(),
            Constants.salt: salt,
            Constants.senderCurrentEphemeralKey: senderPrivateKey.publicKey.rawRepresentation,
            Constants.recipientCurrentEphemeralKeyNumber: (result.keyType == 2 || result.keyType == 3) ? result.keyNumber : 0,
            Constants.signature : signatureOfDigestForEncryptedPayload,
            Constants.keyType : result.keyType
        ] as [String: Any]
       
        var ref: DocumentReference? = nil
        ref = document.addDocument(data: documentDataToSendToServer) { err in
            if let err = err {
                
                GlobalMMVM.conversations[GlobalMMVM.selectedConversationId].messagesinConversation.append(.init(documentId: UUID().uuidString, timeSentTimestamp: Timestamp(date: Date()), timeExpiresTimestamp: Timestamp(date: Date() + 90), clearText: "Error: unable to send message \"\(String(data: unencryptedMessageToSend, encoding: .utf8) ?? "")\" due to error: \(err)", messageType: Constants.messageTypeError, fromId: fromId))

                // manually controls SwiftUI refresh to reduce # of refreshes
                GlobalMMVM.forceRefresh += 1  
                
                UIApplication.shared.endBackgroundTask(backgroundUploadID)
            }
            else {
                // successfully sent message
                GlobalMMVM.conversations[GlobalMMVM.selectedConversationId].messagesinConversation.append(.init(documentId: ref!.documentID, timeSentTimestamp: Timestamp(date: Date()), timeExpiresTimestamp: Timestamp(date: expireAt), clearText: String(data: unencryptedMessageToSend, encoding: .utf8) ?? "", messageType:  foundInAddressBookAndUsingOTP ? Constants.messageTypeTextWithOTP : Constants.messageTypeText, fromId: fromId))
                
                GlobalMMVM.conversations[GlobalMMVM.selectedConversationId].lastMessageTime = Date()

                // manually controls SwiftUI refresh to reduce # of refreshes
                GlobalMMVM.forceRefresh += 1 

                // uses Secure Enclave to generate AES-256 key used for encrypting data at rest on top of iOS encryption
                GlobalMMVM.saveConversationsToFile() 
               
                // ensure we also save the addressbook since our ephemeral keys are stored there!
                // uses Secure Enclave to generate AES-256 key used for encrypting data at rest on top of iOS encryption
                GlobalMMVM.saveAddressBookToFile() 
                
                UIApplication.shared.endBackgroundTask(backgroundUploadID)
            }
        }

        return true

    }
    
    return false
}
