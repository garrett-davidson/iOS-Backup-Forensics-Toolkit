//
//  ForensicsModule.swift
//  iOS Backup Forensics Toolkit
//
//  Created by Garrett Davidson on 12/3/14.
//  Copyright (c) 2014 Garrett Davidson. All rights reserved.
//

import Foundation

@objc public class ForensicsModule {

    public let manager = NSFileManager.defaultManager()

    public let bundle: ForensicsBundleProtocol

    public var emailAccounts = [String]()

    public enum Services: String {
        case Facebook = "Facebook"
        case Twitter = "Twitter"
        case Tumblr = "Tumblr"
    }

    public var oauthTokens = Dictionary<String, Dictionary<String, Dictionary<String, [String]>>>()
    public var passwords = Dictionary<String, String>()

    public init(bundle: ForensicsBundleProtocol) {
        self.bundle = bundle
    }

    public func pathForApplication(#identifier: String) -> String? {
        let path = "\(bundle.originalDirectory)/Applications/\(identifier)/"

        if (manager.fileExistsAtPath(path)) {
            return path
        }

        else
        {
            return nil
        }
    }

    public func saveToken(token: String, fromApp identifier:String, forService service: Services) {
        saveToken(token, fromApp: identifier, forService: service.rawValue, forAccount: nil)
    }

    public func saveToken(token: String, fromApp identifier: String, forService service: String) {
        saveToken(token, fromApp: identifier, forService: service, forAccount: nil)
    }

    public func saveToken(token: String, fromApp identifier: String, forService service: Services, forAccount account:String?) {
        saveToken(token, fromApp: identifier, forService: service.rawValue, forAccount: account)
    }

    public func saveToken(token: String, fromApp identifier: String, forService service: String, forAccount account:String?) {

        //default username for unidentified tokens
        var user = account
        if (user == nil)
        {
            user = "Unknown"
        }


        //make sure nothing is nil and going to crash
        if (oauthTokens[service] == nil)
        {
            oauthTokens[service] = Dictionary<String, Dictionary<String, [String]>>()
        }
        if (oauthTokens[service]![user!] == nil)
        {
            oauthTokens[service]![user!] = Dictionary<String, [String]>()
        }
        if (oauthTokens[service]![user!]![identifier] == nil)
        {
            oauthTokens[service]![user!]![identifier] = [String]()
        }

        oauthTokens[service]![user!]![identifier]!.append(token)
    }

    public func dictionaryFromPath(relativePath: String, forIdentifier identifier: String) -> NSDictionary? {
        let applicationPath = pathForApplication(identifier: identifier)

        if (applicationPath != nil)
        {
            let dictPath = applicationPath! + relativePath
            if (manager.fileExistsAtPath(dictPath)) {
                return NSDictionary(contentsOfFile: dictPath)
            }
        }

        return nil
    }

    public func arrayFromPath(relativePath: String, forIdentifier identifier: String) -> NSArray? {
        let applicationPath = pathForApplication(identifier: identifier)

        if (applicationPath != nil)
        {
            let arrayPath = applicationPath! + relativePath
            if (manager.fileExistsAtPath(arrayPath)) {
                return NSArray(contentsOfFile: arrayPath)
            }
        }

        return nil
    }

    public func createInterestingDirectory(relativePath: String) -> String {
        let path = "\(bundle.interestingDirectory)/\(relativePath)/"
        manager.createDirectoryAtPath(path, withIntermediateDirectories: true, attributes: nil, error: nil)
        return path
    }

    public func description() -> String {
        return ""
    }

    public func pullFacebookAccessTokenFromApp(#identifier: String)
    {
        //Can't use default value because path depends on identifier
        pullFacebookAccessTokenFromApp(identifier: identifier, customPath: nil)
    }

    public func pullFacebookAccessTokenFromApp(#identifier: String, customPath: String?) {
        var path = "Library/Preferences/\(identifier).plist"

        if (customPath != nil)
        {
            path = customPath!
        }

        let dict = dictionaryFromPath(path, forIdentifier: identifier)

        if (dict != nil)
        {
            let key1 = dict!["FBAccessTokenInformationKey"] as! NSDictionary?

            if (key1 != nil)
            {
                let token = key1!["com.facebook.sdk:TokenInformationTokenKey"] as! String?

                if (token != nil)
                {
                    saveToken(token!, fromApp:identifier, forService: .Facebook)
                }
            }
        }
    }
    
    public func savePassword(password: String, forAccount account: String) {
        passwords[account] = password
    }

    public func pullXMLValue(path:String, tag: String) -> String? {
        let xmlString = NSString(contentsOfFile: path, encoding: NSUTF8StringEncoding, error: nil)

        let startIndex = xmlString!.rangeOfString("<\(tag)>").location
        let endIndex = xmlString!.rangeOfString("</\(tag)>").location

        return xmlString!.substringWithRange(NSMakeRange(startIndex, endIndex-startIndex))
    }
}

@objc public protocol ForensicsBundleProtocol {
    var name: String {get}
    var modules: [ForensicsModuleProtocol] {get}
    var originalDirectory: String {get}
    var interestingDirectory: String {get}

    static func loadBundleWithDirectories(#originalDirectory: String, interestingDirectory: String) -> ForensicsBundleProtocol
}

@objc public protocol ForensicsModuleProtocol {
    var oauthTokens: Dictionary<String, Dictionary<String, Dictionary<String, [String]>>> {get}
    var passwords: Dictionary<String, String> {get}
    var name: String {get}
    var appIdentifiers: [String] {get}
    var bundle: ForensicsBundleProtocol {get}

    func analyze()
    func description() -> String
}