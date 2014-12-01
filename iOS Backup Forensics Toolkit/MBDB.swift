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

    init(path: String, outDirectory: String) {
        inputStream = NSInputStream(fileAtPath: path + "/Manifest.mbdb")!
        inputStream.open()

        backupDirectory = path
        outputDirectory = outDirectory
    }

    func recreateFilesytem() {
        readHeader()
        while (handleRecord()) {

        }

        println("Finished recreating file system")
    }

    func handleRecord() -> Bool {

        let domain = readString()
        let path = readString()
        let linkTarget = readString()
        let hash = readString()
        let encryptionKey = readString()

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
            moveRecord(domain, path: path)
        }

        return inputStream.hasBytesAvailable
    }

    func getFileName(#domain: String, path: String) -> String {
        return (domain + "-" + path).sha1()
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

        let newURL = NSURL(fileURLWithPath: "\(outputDirectory)/Original/\(topFolder)/\(path)")!

        return newURL
    }

    func moveRecord(domain: String, path:String) {
        let originalURL = NSURL(fileURLWithPath: backupDirectory + "/" + getFileName(domain: domain, path: path))!
        let url = getNewURL(domain: domain, path: path)
        let directoryURL = url.URLByDeletingLastPathComponent!

        var error: NSError?
        manager.createDirectoryAtURL(directoryURL, withIntermediateDirectories: true, attributes: nil, error: &error)
        if (error != nil)
        {
            println(error!)
        }

        manager.copyItemAtURL(originalURL, toURL: url, error: &error)

        //DEBUG
//        manager.moveItemAtURL(originalURL, toURL: NSURL(fileURLWithPath: "/Users/garrettdavidson/GenTest/Used/" + originalURL.lastPathComponent)!, error: nil)

        if (error != nil)
        {
            println(error!)
        }
    }

    func readHeader() {
        readBytes(6)
        //TODO
        //check header validity
    }

    func readString() -> String {
        let length = readInt(2)
        if (length == 65535)
        { return "" }
        return readString(length)
    }

    func readString(length: Int) -> String {
        var buffer = readBytes(length)

        let string = NSString(bytes: buffer, length: length, encoding: NSASCIIStringEncoding)

        if (string != nil)
        {
            return string!
        }

        else
        {
            return ""
        }
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

extension String {
    func sha1() -> String {
        let data = self.dataUsingEncoding(NSUTF8StringEncoding)!
        var digest = [UInt8](count:Int(CC_SHA1_DIGEST_LENGTH), repeatedValue: 0)
        CC_SHA1(data.bytes, CC_LONG(data.length), &digest)
        let output = NSMutableString(capacity: Int(CC_SHA1_DIGEST_LENGTH))
        for byte in digest {
            output.appendFormat("%02x", byte)
        }
        return output
    }
}