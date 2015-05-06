// Playground - noun: a place where people can play

import Cocoa
import CommonCrypto

let backupDir = "/Users/garrettdavidson/Dropbox/Dev/OS X/iOS Backup Forensics Toolkit Testing/iOS-Backup-Decryption-Playground.playground/Resources/f8ccdfcda181e284fb5564386c4836c8f5e8e4cd/"
let backupPass = "w11ru13r"
let testFileName = "32835393ae8fea393f9f603ac15738a3d156538b"

let classKeyTags = ["CLAS","WRAP","WPKY", "KTYP", "PBKY"]
let keybagTypes = ["System", "Backup", "Escrow", "OTA (icloud)"]
let wrapDevice = 1
let wrapPasscode = 2


class Keybag {
    var type: Int = -1
    var uuid: NSData?
    var wrap: Int?
    var deviceKey: String?
    var attrs = NSMutableDictionary()
    var classKeys = NSMutableDictionary()
    var KeyBagKeys: NSMutableDictionary?

    init(blob: NSData) {
        parseBinary(blob)
    }

    //finished
    func parseBinary(blob: NSData) {
        var currentClassKey: NSMutableDictionary?

        var i = 0
        var skipped = false
        while (i+8 <= blob.length) {
            let tag = NSString(data: blob.subdataWithRange(NSMakeRange(i, 4)), encoding: NSUTF8StringEncoding)!

            var unsignedLength: UInt32 = 0
            blob.subdataWithRange(NSMakeRange(i+4, 4)).getBytes(&unsignedLength, length: 4)
            let length = Int(CFSwapInt32BigToHost(unsignedLength))

            var data: AnyObject = blob.subdataWithRange(NSMakeRange(i + 8, length))


            if length == 4
            {
                var a: UInt32 = 0
                data.getBytes(&a)
                data = Int(CFSwapInt32BigToHost(a))
            }


            if (tag == "TYPE")
            {
                self.type = data as Int
                if self.type > 3
                {
                    println("FAIL: keybag type > 3 : \(self.type)")
                }
            }

            else if (tag == "UUID")
            {
                currentClassKey
                self.classKeys
//                if (!skippedUUID)
//                {
//                    skippedUUID = true
//                }
//
//                else
//                {
                    if let myclass = currentClassKey?["CLAS"] as? NSCopying
                    {
                        self.classKeys[myclass] = currentClassKey!
                    }
                    currentClassKey = NSMutableDictionary(object: data, forKey: "UUID")
//                }
            }

//            else if (tag == "WRAP" && !skipped)
//            {
//                currentClassKey
//                skipped = true
//            }

            else if contains(classKeyTags, tag)
            {
                currentClassKey![tag] = data
            }

            else
            {
                self.attrs[tag] = data
            }

            i += 8 + length

        }

        if let myclass = currentClassKey?["CLAS"] as? NSCopying
        {
            self.classKeys[myclass] = currentClassKey!
        }
    }

    func printClassKeys()
    {
        println("== Keybag")
        println("Keybag type: \(keybagTypes[self.type]) keybag (\(self.type))")

        let version: AnyObject = self.attrs["VERS"]!
        println("Keybag version: \(version)")
        
        let iterations: AnyObject = self.attrs["ITER"]!; let salt: AnyObject = self.attrs["SALT"]!
        println("Keybag iterations: \(iterations), iv=\(salt)")
        //TODO
        //FINISH
    }

    //finished
    func unlockWithPasscode(passcode: String) -> Bool
    {
        let salt = keybag!.attrs["SALT"]! as NSData
        let iterations = keybag!.attrs["ITER"] as UInt
        let passcodeKey = deriveKey(passcode, salt, UInt32(kCCPRFHmacAlgSHA1), uint(iterations), 32)

        for classKey in (classKeys.allValues as [NSMutableDictionary])
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

    //finished
    func AESUnwrap(kek:[UInt8], wrapped:NSData) -> NSData
    {
        var C = [UInt64]()

        for i in 0...wrapped.length/8-1
        {
            var a: UInt64 = 0
            let subdata = wrapped.subdataWithRange(NSMakeRange(i*8, 8))
            subdata.getBytes(&a)
            C.append(CFSwapInt64HostToBig(a))
        }

        let n = C.count - 1


        for var j = 5; j >= 0; j--
        {
//            println("j = \(j)")
            for var i = n; i >= 1; i--
            {
//                println("i = \(i)")
                var todec = CFSwapInt64HostToBig(C[0] ^ UInt64(n * j + i))
                let cipherData = NSMutableData(bytes: &todec, length: 8)
                todec = CFSwapInt64HostToBig(C[i])
                cipherData.appendBytes(&todec, length: 8)
//                println(cipherData)

                var outBytes = [UInt8](count: cipherData.length, repeatedValue: 0)
                var outCount: UInt = 0

                var iv = 0
                CCCrypt(UInt32(kCCDecrypt) as CCOperation, UInt32(kCCAlgorithmAES) as CCAlgorithm, UInt32(0) as CCOptions, kek, UInt(kek.count), &iv, cipherData.bytes, UInt(cipherData.length), &outBytes, UInt(outBytes.count), &outCount)

                let outData = NSData(bytes: &outBytes, length: Int(outCount))
//                println(outData)

                outData.getBytes(&C[0], range: NSMakeRange(0, 8))
                C[0] = CFSwapInt64HostToBig(C[0])
                outData.getBytes(&C[i], range: NSMakeRange(8, outData.length-8))
                C[i] = CFSwapInt64HostToBig(C[i])
//                println(R[i])
            }
        }

        if C[0] != 0xa6a6a6a6a6a6a6a6
        {
            println("AES decryption error")
        }

//        println(R[1])
        let returnData = NSMutableData()
        for i in 1...C.count-1
        {
            var a = CFSwapInt64HostToBig(C[i])
            returnData.appendBytes(&a, length: 8)
        }
        return returnData
    }

    //finished
    func unwrapKeyForClass(protectionClass: Int, persistentKey: inout [UInt8]) -> NSData
    {
        let classKey = keybag!.classKeys[protectionClass]!["KEY"]! as NSData

        let persistentKeyData = NSData(bytes: persistentKey, length: persistentKey.count)

        if (persistentKey.count != 0x28)
        {
            println("Invalid key length")
        }

        var classKeyBuffer = [UInt8](count:classKey.length, repeatedValue:0)
        classKey.getBytes(&classKeyBuffer)

        return AESUnwrap(classKeyBuffer, wrapped:persistentKeyData)
    }

    //finished
    func AESDecryptCBC(a: NSData, key: [UInt8]) -> NSData
    {
        var data = a.mutableCopy() as NSMutableData
        if a.length % 16 > 0
        {
            println("AESdecryptCBC: data length not /16, truncating")
            data = a.subdataWithRange(NSMakeRange(0, (data.length/16)*16)).mutableCopy() as NSMutableData
        }

        var outBuffer = [UInt8](count: data.length, repeatedValue: 0)
        var outLength:UInt = 0
        var f = 0
        CCCrypt(UInt32(kCCDecrypt), UInt32(kCCAlgorithmAES), UInt32(0), key, UInt(key.count), &f, data.bytes, UInt(data.length), &outBuffer, UInt(data.length), &outLength)
        let outData = NSData(bytes: &outBuffer, length: Int(outLength))


        println("== decrypted data: ")
        println(outData)
        return outData
    }
}

func deriveKey(password : String, salt : NSData, prf: CCPseudoRandomAlgorithm, rounds: uint, derivedKeyLength: UInt) -> [UInt8]
{
    var derivedKey = [UInt8](count:Int(derivedKeyLength), repeatedValue: 0)
    var status : Int32 = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, UInt(password.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)), UnsafePointer<UInt8>(salt.bytes), UInt(salt.length), prf, rounds, &derivedKey, UInt(derivedKey.count))
    if(status != Int32(kCCSuccess))
    {
        NSLog("ERROR: CCKeyDerivationPBDK failed with stats \(status).")
        fatalError("ERROR: CCKeyDerivationPBDK failed.")
    }
    return derivedKey
}

class MBDB: NSObject {

    let inputStream: NSInputStream

    let backupDirectory: String
    let outputDirectory: String

    //finished
    init(path: String, outDirectory: String) {
        inputStream = NSInputStream(fileAtPath: path + "/Manifest.mbdb")!
        inputStream.open()

        backupDirectory = path
        outputDirectory = outDirectory
    }

    //finished
    func recreateFilesytem() {
        readHeader()
        while (handleRecord()) {

        }
        
        println("Finished recreating file system")
    }

    func handleRecord() -> Bool {

        let domain = readString()
        let path = readActualString()
        let linkTarget = readString()
        let hash = readString()
        var encryptionKey = readString()

        let mode = readInt(2)
        let inodeNumber = readInt(8)
        let userId = readInt(4)
        let groupId = readInt(4)
        let lastModified = readInt(4)
        let lastAccessed = readInt(4)
        let created = readInt(4)
        let fileSize = readInt(8)
        let protectionClass = readInt(1)
        let propertyCount = readInt(1)

        var properties = Dictionary<String, String>()

        if propertyCount > 0
        {
            for _ in 1...propertyCount {
                let key = readActualString()
                let value = readActualString()
                properties[key] = value
            }
        }

        if path.rangeOfString("BITUpdateManager.plist") != nil
        {
            let contents = NSData(contentsOfFile: backupDir + testFileName)
            encryptionKey.removeRange(0...3)
            println(NSData(bytes: &encryptionKey, length: encryptionKey.count))
            let key = keybag!.unwrapKeyForClass(protectionClass, persistentKey: encryptionKey)

            var keyBuffer = [UInt8](count: key.length, repeatedValue: 0)
            key.getBytes(&keyBuffer)
            var decryptedData = keybag!.AESDecryptCBC(contents!, key: keyBuffer).subdataWithRange(NSMakeRange(0, fileSize))
        }

        return inputStream.hasBytesAvailable
    }

    func getNewURL(#domain: String, path: String) -> NSURL {
        var topFolder = domain

        let components = domain.componentsSeparatedByString("-")

        if (components.count > 1)
        {
            //            if (components[0] == "AppDomain" || components[0] == "AppDomainGroup")
            //            {
            //                topFolder = "Applications/\(components[1])"
            //            }
            //
            //            else
            if (components[0].rangeOfString("AppDomain") != nil)
            {
                topFolder = "Applications/\(components[1])"
            }
        }

        let newURL = NSURL(fileURLWithPath: "\(outputDirectory)/\(topFolder)/\(path)")!

        return newURL
    }

    func readHeader() {
        readBytes(6)
        //TODO
        //check header validity
    }

    func readActualString() -> String
    {
        let buffer = readString()
        let string = NSString(bytes: buffer, length: buffer.count, encoding: NSASCIIStringEncoding)
        return string == nil ? "" : string!
    }

    func readString() -> [UInt8] {
        let length = readInt(2)
        if (length == 65535)
        { return [UInt8]() }
        return readString(length)
    }

    func readString(length: Int) -> [UInt8] {
        var buffer = readBytes(length)
        return buffer
//        let string = NSString(bytes: buffer, length: length, encoding: NSASCIIStringEncoding)
//
//        if (string != nil)
//        {
//            return string!
//        }
//
//        else
//        {
//            return ""
//        }
    }

    func readInt(length: Int) -> Int {
        var buffer = readBytes(length)

        var total:Int = 0
        for int in buffer
        {
            total <<= 8
            total = total | (0x000000FF & Int(int))
        }

        return total
    }

    func readBytes(length: Int) -> [UInt8] {
        var buffer = [UInt8](count: length, repeatedValue: 0)

        if (length > 0)
        {
            inputStream.read(&buffer, maxLength: length)
        }

        return buffer
    }

}




var keybag: Keybag?
func main() {
    let manifestPlist = NSDictionary(contentsOfFile: backupDir + "Manifest.plist")

    if manifestPlist != nil
    {
        keybag = Keybag(blob: manifestPlist!["BackupKeyBag"]! as NSData)
        keybag!.printClassKeys()
        keybag!.unlockWithPasscode(backupPass)

        let mbdb = MBDB(path: backupDir, outDirectory: "")
        mbdb.recreateFilesytem()
    }
}

func test() {

    main()}


test()
