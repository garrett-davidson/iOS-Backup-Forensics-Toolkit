//
//  MBDB.swift
//  iOS Backup Forensics Toolkit
//
//  Created by Garrett Davidson on 11/30/14.
//  Copyright (c) 2014 Garrett Davidson. All rights reserved.
//

import Foundation

class MBDB: NSObject {

    let manager = NSFileManager.defaultManager()
    let inputStream: NSInputStream

    let backupDirectory: String
    let outputDirectory: String

    let keybag: Keybag?

    init(path: String, outDirectory: String, keybag: Keybag?) {
        inputStream = NSInputStream(fileAtPath: path + "/Manifest.mbdb")!
        inputStream.open()

        backupDirectory = path
        outputDirectory = outDirectory
        self.keybag = keybag
    }

    func recreateFilesytem() {
        do {
            try manager.createDirectoryAtPath(outputDirectory, withIntermediateDirectories: true, attributes: nil)
        } catch _ {
        }
        readHeader()
        while (handleRecord()) {

        }

        print("Finished recreating file system")
    }

    func handleRecord() -> Bool {

        let domain = readString()
        let path = readString()
        let linkTarget = readBuffer()
        let hash = readBuffer()
        var encryptionKey = readBuffer()

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
                let key = readString()
                let value = readString()
                properties[key] = value
            }
        }

        if fileSize > 0
        {
            moveRecord(domain, path: path, protectionClass: protectionClass, encryptionKey: &encryptionKey, fileSize: fileSize)
        }

        return inputStream.hasBytesAvailable
    }

    func getFileName(domain domain: String, path: String) -> String {
        return (domain + "-" + path).sha1()
    }

    func getNewURL(domain domain: String, path: String) -> NSURL {
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

        let newURL = NSURL(fileURLWithPath: "\(outputDirectory)/\(topFolder)/\(path)")

        return newURL
    }

    func moveRecord(domain: String, path:String, protectionClass: Int, inout encryptionKey: [UInt8], fileSize: Int) {
        let originalURL = NSURL(fileURLWithPath: backupDirectory + "/" + getFileName(domain: domain, path: path))
        let url = getNewURL(domain: domain, path: path)
        let directoryURL = url.URLByDeletingLastPathComponent!

        var error: NSError?
        do {
            try manager.createDirectoryAtURL(directoryURL, withIntermediateDirectories: true, attributes: nil)
        } catch var error1 as NSError {
            error = error1
        }
        if (error != nil)
        {
            print(error!)
        }

        //unencrypted backup
        if keybag == nil
        {
            do {
                try manager.copyItemAtURL(originalURL, toURL: url)
            } catch var error1 as NSError {
                error = error1
            }
        }

        //encrypted backup
        else
        {
            if let cipherData = NSData(contentsOfURL: originalURL)
            {
                encryptionKey.removeRange(0...3)
                let key = keybag!.unwrapKeyForClass(protectionClass, persistentKey: &encryptionKey)

                var keyBuffer = [UInt8](count: key.length, repeatedValue: 0)
                key.getBytes(&keyBuffer, length:key.length)
                var decryptedData = keybag!.AESDecryptCBC(cipherData, key: keyBuffer) as NSData

                if decryptedData.length > fileSize
                {
                    decryptedData = decryptedData.subdataWithRange(NSMakeRange(0, fileSize))
                }

                decryptedData.writeToURL(url, atomically: true)
            }
            else
            {
                print("Unable to find file:")
                print(originalURL)
            }
        }

        if (error != nil)
        {
            print(error!)
        }
    }

    func readHeader() {
        readBytes(6)
        //TODO
        //check header validity
    }

    func readString() -> String
    {
        let buffer = readBuffer()
        let string = NSString(bytes: buffer, length: buffer.count, encoding: NSASCIIStringEncoding) as? String
        return string == nil ? "" : string!
    }

    func readBuffer() -> [UInt8] {
        let length = readInt(2)
        if (length == 65535)
        { return [UInt8]() }
        return readBuffer(length)
    }

    func readBuffer(length: Int) -> [UInt8] {
        return readBytes(length)
    }

    func readInt(length: Int) -> Int {
        let buffer = readBytes(length)

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

extension String {
    func sha1() -> String {
        let data = self.dataUsingEncoding(NSUTF8StringEncoding)!
        var digest = [UInt8](count:Int(CC_SHA1_DIGEST_LENGTH), repeatedValue: 0)
        CC_SHA1(data.bytes, CC_LONG(data.length), &digest)
        let output = NSMutableString(capacity: Int(CC_SHA1_DIGEST_LENGTH))
        for byte in digest {
            output.appendFormat("%02x", byte)
        }
        return output as String
    }
}