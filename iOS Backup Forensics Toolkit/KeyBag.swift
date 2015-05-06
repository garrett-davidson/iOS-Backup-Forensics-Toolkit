//
//  KeyBag.swift
//  iOS Backup Forensics Toolkit
//
//  Created by Garrett Davidson on 1/1/15.
//  Copyright (c) 2015 Garrett Davidson. All rights reserved.
//

import Foundation

let classKeyTags = ["CLAS","WRAP","WPKY", "KTYP", "PBKY"]
let keybagTypes = ["System", "Backup", "Escrow", "OTA (iCloud)"]
let wrapDevice = 1
let wrapPasscode = 2

class Keybag {
    var type: Int = -1
    //    let deviceKey: String
    let attrs = NSMutableDictionary()
    let classKeys = NSMutableDictionary()
    //    let KeyBagKeys: NSMutableDictionary

        init(blob: NSData) {
        var currentClassKey: NSMutableDictionary?

        var i = 0
        while (i+8 <= blob.length)
        {
            let tag = NSString(data: blob.subdataWithRange(NSMakeRange(i, 4)), encoding: NSUTF8StringEncoding)!
            let length = Int(packInt32(blob.subdataWithRange(NSMakeRange(i+4, 4))))
            var data: AnyObject = blob.subdataWithRange(NSMakeRange(i + 8, length))

            if length == 4
            {
                data = Int(packInt32(data as! NSData))
            }

            if tag == "TYPE"
            {
                self.type = data as! Int
                if self.type > 3
                {
                    println("FAIL: keybag type > 3 : \(self.type)")
                }
            }

            else if tag == "UUID"
            {
                if let currentClass = currentClassKey?["CLAS"] as? NSCopying
                {
                    self.classKeys[currentClass] = currentClassKey!
                }
                currentClassKey = NSMutableDictionary(object: data, forKey: "UUID")
            }

            else if contains(classKeyTags, tag as String)
            {
                currentClassKey![tag] = data
            }

            else
            {
                self.attrs[tag] = data
            }

            i += 8 + length
        }

        if let currentClass = currentClassKey?["CLAS"] as? NSCopying
        {
            self.classKeys[currentClass] = currentClassKey!
        }
    }

    //32 bit is BIG to HOST
    func packInt32(data: NSData) -> UInt32
    {
        var returnInt: UInt32 = 0
        data.getBytes(&returnInt, length: 4)
        return (CFSwapInt32BigToHost(returnInt))
    }

    //64 bit is HOST to BIG
    func packInt64(data: NSData) -> UInt64
    {
        var returnInt: UInt64 = 0
        data.getBytes(&returnInt, length: 8)
        return (CFSwapInt64HostToBig(returnInt))
    }

    func unlockWithPasscode(passcode: String) -> Bool
    {
        let salt = attrs["SALT"]! as! NSData
        let iterations = attrs["ITER"] as! UInt
        let passcodeKey = deriveKey(passcode, salt: salt, prf: UInt32(kCCPRFHmacAlgSHA1), rounds: uint(iterations), derivedKeyLength: 32)

        for classKey in (classKeys.allValues as! [NSMutableDictionary])
        {
            var k = classKey["WPKY"] as? NSData
            if k != nil
            {
                let wrap = classKey["WRAP"] as? Int
                if (wrap != nil && wrap! & wrapPasscode > 0)
                {
                    k = AESUnwrap(passcodeKey, wrapped: k!)

                    if (k != nil)
                    {
                        classKey["KEY"] = k!
                    }

                    else
                    {
                        return false
                    }
                }
            }
        }

        return true
    }

    func deriveKey(password : String, salt : NSData, prf: CCPseudoRandomAlgorithm, rounds: uint, derivedKeyLength: UInt) -> [UInt8]
    {
        var derivedKey = [UInt8](count:Int(derivedKeyLength), repeatedValue: 0)
        
        var status : Int32 = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2) as CCPBKDFAlgorithm, password, Int(password.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)), UnsafePointer<UInt8>(salt.bytes), Int(salt.length), prf, rounds, &derivedKey, Int(derivedKey.count))
        if(status != Int32(kCCSuccess))
        {
            NSLog("ERROR: CCKeyDerivationPBDK failed with stats \(status).")
            fatalError("ERROR: CCKeyDerivationPBDK failed.")
        }
        return derivedKey
    }

    func AESUnwrap(kek:[UInt8], wrapped:NSData) -> NSData
    {
        var C = [UInt64]()

        for i in 0...wrapped.length/8-1
        {
            C.append(packInt64(wrapped.subdataWithRange(NSMakeRange(i*8, 8))))
        }

        let n = C.count - 1

        for var j = 5; j >= 0; j--
        {
            for var i = n; i >= 1; i--
            {
                var todec = CFSwapInt64HostToBig(C[0] ^ UInt64(n * j + i))
                let cipherData = NSMutableData(bytes: &todec, length: 8)
                todec = CFSwapInt64HostToBig(C[i])
                cipherData.appendBytes(&todec, length: 8)

                var outBytes = [UInt8](count: cipherData.length, repeatedValue: 0)
                var outCount: size_t = 0

                var iv = 0
                CCCrypt(UInt32(kCCDecrypt) as CCOperation, UInt32(kCCAlgorithmAES) as CCAlgorithm, UInt32(0) as CCOptions, kek, Int(kek.count) as size_t, &iv, cipherData.bytes, Int(cipherData.length) as size_t, &outBytes, Int(outBytes.count) as size_t, &outCount)

                let outData = NSData(bytes: &outBytes, length: Int(outCount))

                outData.getBytes(&C[0], range: NSMakeRange(0, 8))
                C[0] = CFSwapInt64HostToBig(C[0])
                outData.getBytes(&C[i], range: NSMakeRange(8, outData.length-8))
                C[i] = CFSwapInt64HostToBig(C[i])
            }
        }

        if C[0] != 0xa6a6a6a6a6a6a6a6
        {
            println("AES decryption error")
        }

        let returnData = NSMutableData()
        for i in 1...C.count-1
        {
            var a = CFSwapInt64HostToBig(C[i])
            returnData.appendBytes(&a, length: 8)
        }
        return returnData
    }

    func unwrapKeyForClass(protectionClass: Int, persistentKey: inout [UInt8]) -> NSData
    {
        let classKey = classKeys[protectionClass]!["KEY"]! as! NSData

        let persistentKeyData = NSData(bytes: persistentKey, length: persistentKey.count)

        if (persistentKey.count != 0x28)
        {
            println("Invalid key length")
        }

        var classKeyBuffer = [UInt8](count:classKey.length, repeatedValue:0)
        classKey.getBytes(&classKeyBuffer, length: classKey.length)

        return AESUnwrap(classKeyBuffer, wrapped:persistentKeyData)
    }

    func AESDecryptCBC(a: NSData, key: [UInt8]) -> NSData
    {
        var data = a.mutableCopy() as! NSMutableData
        if a.length % 16 > 0
        {
            println("AESdecryptCBC: data length not /16, truncating")
            data = a.subdataWithRange(NSMakeRange(0, (data.length/16)*16)).mutableCopy() as! NSMutableData
        }

        var outBuffer = [UInt8](count: data.length, repeatedValue: 0)
        var outLength:size_t = 0
        var f = 0
        CCCrypt(UInt32(kCCDecrypt) as CCOperation, UInt32(kCCAlgorithmAES) as CCAlgorithm, UInt32(0) as CCOptions, key, Int(key.count) as size_t, &f, data.bytes, Int(data.length) as size_t, &outBuffer, Int(data.length) as size_t, &outLength)
        let outData = NSData(bytes: &outBuffer, length: Int(outLength))
        
        
//        println("== decrypted data: ")
//        println(outData)
        return outData
    }
}