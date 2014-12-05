//
//  ForensicsModule.swift
//  iOS Backup Forensics Toolkit
//
//  Created by Garrett Davidson on 12/3/14.
//  Copyright (c) 2014 Garrett Davidson. All rights reserved.
//

import Foundation

class ForensicsModule{

    let originalDirectory: String
    let interestingDirectory: String

    let manager = NSFileManager.defaultManager()

    var emailAccounts = [String]()

    enum Services: String {
        case Facebook = "Facebook"
        case Twitter = "Twitter"
    }

    init(outputDirectory: String) {
        self.originalDirectory = outputDirectory + "/Original/"
        self.interestingDirectory = outputDirectory + "/Interesting/"
    }

    func pathForApplication(#identifier: String) -> String? {
        let path = "\(originalDirectory)Applications/\(identifier)/"

        if (manager.fileExistsAtPath(path)) {
            return path
        }

        else
        {
            return nil
        }
    }

    func saveToken(token: String, fromApp identifier:String, forService service: Services) {
        saveToken(token, fromApp: identifier, forService: service.rawValue, forAccount: nil)
    }

    func saveToken(token: String, fromApp identifier: String, forService service: String) {
        saveToken(token, fromApp: identifier, forService: service, forAccount: nil)
    }

    func saveToken(token: String, fromApp identifier: String, forService service: Services, forAccount account:String?) {
        saveToken(token, fromApp: identifier, forService: service.rawValue, forAccount: account)
    }

    func saveToken(token: String, fromApp identifier: String, forService service: String, forAccount account:String?) {

        //default username for unidentified tokens
        var user = account
        if (user == nil)
        {
            user = "Unknown"
        }


        //make sure nothing is nil and going to crash
        if (ViewController.InterestingData.oauthTokens[service] == nil)
        {
            ViewController.InterestingData.oauthTokens[service] = Dictionary<String, Dictionary<String, [String]>>()
        }
        if (ViewController.InterestingData.oauthTokens[service]![user!] == nil)
        {
            ViewController.InterestingData.oauthTokens[service]![user!] = Dictionary<String, [String]>()
        }
        if (ViewController.InterestingData.oauthTokens[service]![user!]![identifier] == nil)
        {
            ViewController.InterestingData.oauthTokens[service]![user!]![identifier] = [String]()
        }

        ViewController.InterestingData.oauthTokens[service]![user!]![identifier]!.append(token)
    }

    func dictionaryFromPath(relativePath: String, forIdentifier identifier: String) -> NSDictionary? {
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

    func arrayFromPath(relativePath: String, forIdentifier identifier: String) -> NSArray? {
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

    func createInterestingDirectory(relativePath: String) -> String {
        let path = "\(interestingDirectory)/\(relativePath)/"
        manager.createDirectoryAtPath(path, withIntermediateDirectories: true, attributes: nil, error: nil)
        return path
    }

    func pullFacebookAccessTokenFromApp(identifier: String)
    {
        //Can't use default value because path depends on identifier
        pullFacebookAccessTokenFromApp(identifier, customPath: nil)
    }

    func pullFacebookAccessTokenFromApp(identifier: String, customPath: String?) {
        var path = "Library/Preferences/\(identifier).plist"

        if (customPath != nil)
        {
            path = customPath!
        }

        let dict = dictionaryFromPath(path, forIdentifier: identifier)

        if (dict != nil)
        {
            let key1 = dict!["FBAccessTokenInformationKey"] as NSDictionary?

            if (key1 != nil)
            {
                let token = key1!["com.facebook.sdk:TokenInformationTokenKey"] as String?

                if (token != nil)
                {
                    saveToken(token!, fromApp:identifier, forService: .Facebook)
                }
            }
        }
    }
    
    func savePassword(password: String, forAccount account: String) {
        ViewController.InterestingData.passwords[account] = password
    }
}

protocol ForensicsBundleProtocol {
    var name: String {get}
    var modules: [ForensicsModule] {get}
}

protocol ForensicsModuleProtocol {
    var name: String {get}
    var appIdentifiers: [String] {get}

    func analyze()
}