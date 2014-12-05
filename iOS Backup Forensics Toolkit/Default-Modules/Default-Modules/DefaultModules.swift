//
//  DefaultModules.swift
//  iOS Backup Forensics Toolkit
//
//  Created by Garrett Davidson on 12/3/14.
//  Copyright (c) 2014 Garrett Davidson. All rights reserved.
//

import Foundation
import ForensicsModuleFramework

@objc class DefaultModulesBundle: ForensicsBundleProtocol {
    let name = "Default"
    let originalDirectory: String
    let interestingDirectory: String
    var modules: [ForensicsModuleProtocol] = [ForensicsModuleProtocol]()

    class func loadBundleWithDirectories(#originalDirectory: String, interestingDirectory: String) -> ForensicsBundleProtocol {
        let bundle = DefaultModulesBundle(originalDirectory: originalDirectory, interestingDirectory: interestingDirectory)

        bundle.modules = [
            MobileMail(bundle: bundle),
            MobileSafari(bundle: bundle),
            Twitter(bundle: bundle),
            BTSync(bundle: bundle),
            PhotoVault(bundle: bundle),
            Evernote(bundle: bundle),
            GoogleChrome(bundle: bundle),
            GroupMe(bundle: bundle),
            Lumosity(bundle: bundle),
            Manything(bundle: bundle),
            NikePlus(bundle: bundle),
            Friendly(bundle: bundle),
            Pandora(bundle: bundle),
            SnapGrab(bundle: bundle),
            Viggle(bundle: bundle),
            FacebookSDKTokens(bundle: bundle)
        ]

        return bundle
    }

    init(originalDirectory: String, interestingDirectory: String) {
        self.originalDirectory = originalDirectory
        self.interestingDirectory = interestingDirectory
    }

}

@objc class MobileMail: ForensicsModule, ForensicsModuleProtocol {

    let name = "Mobile Mail"
    let appIdentifiers = ["com.apple.mobilemail"]

    func analyze() {
        //        let emailsDict = dictionaryFromPath("Library/Preferences/com.apple.MailAccount-ExtProperties.plist", forIdentifier: "com.apple.mobilemail")
        //
        //        if (emailsDict != nil)
        //        {
        //
        //        }

        var vips = Dictionary<String, [String]>()
        let vipDict = super.dictionaryFromPath("Library/Preferences/com.apple.mobilemail.plist", forIdentifier: "com.apple.mobilemail")

        if (vipDict != nil)
        {
            let vipArray = vipDict!["VIP-senders"] as Dictionary<String, NSDictionary>?

            if (vipArray != nil)
            {

                for vip in vipArray!.values
                {
                    vips[(vip["n"]! as String)] = (vip["a"]! as [String])
                }
                
                NSDictionary(dictionary: vips).writeToFile(createInterestingDirectory("Mail") + "/VIPs.plist", atomically: true)
            }
        }
    }

}

@objc class MobileSafari: ForensicsModule, ForensicsModuleProtocol {

    let name = "Mobile Safari"
    let appIdentifiers = ["com.apple.mobilesafari"]

    func analyze() {
        //Recent searches
        let mobileSafari = dictionaryFromPath("Library/Preferences/com.apple.mobilesafari.plist", forIdentifier: "com.apple.mobilesafari")
        if (mobileSafari != nil)
        {
            var recentSearches = mobileSafari!["RecentWebSearches"] as NSArray?

            if (recentSearches != nil)
            {
                if (recentSearches!.count > 0)
                {
                    recentSearches!.writeToFile(createInterestingDirectory("Safari") + "/recent-searches.plist", atomically: true)
                }
            }
        }

        //TODO
        //History

        //Open tabs
        let suspendedState = dictionaryFromPath("Library/Safari/SuspendState.plist", forIdentifier: "com.apple.mobilesafari")
        if (suspendedState != nil)
        {
            //TODO
            //Add private browsing

            let regularBrowsing = suspendedState!["SafariStateDocuments"]! as [NSDictionary]
            var tabs = Dictionary<String, String>()

            for tab in regularBrowsing
            {
                tabs[(tab["SafariStateDocumentTitle"]! as String)] = (tab["SafariStateDocumentUserVisibleURL"]! as String)
            }

            NSDictionary(dictionary: tabs).writeToFile(bundle.interestingDirectory + "/Safari/open-tabs.plist", atomically: true)

            let privateBrowsing = suspendedState!["SafariStatePrivateDocuments"] as [NSDictionary]?

            if (privateBrowsing != nil)
            {
                var privateTabs = Dictionary<String, String>()

                for tab in privateBrowsing!
                {
                    privateTabs[(tab["SafariStateDocumentTitle"]! as String)] = (tab["SafariStateDocumentUserVisibleURL"]! as String)
                }

                NSDictionary(dictionary: privateTabs).writeToFile(bundle.interestingDirectory + "/Safari/open-private-tabs.plist", atomically: true)
            }
        }
        
        //Local storage
        let safariPath = pathForApplication(identifier: "com.apple.mobilesafari")
        if (safariPath != nil)
        {
            manager.copyItemAtPath(safariPath! + "/Library/WebKit/WebsiteData/LocalStorage/", toPath: bundle.interestingDirectory + "/Safari/LocalStorage", error: nil)
        }
    }

}

@objc class Twitter: ForensicsModule, ForensicsModuleProtocol {

    let name = "Twitter"
    let appIdentifiers = ["com.atebits.Tweetie2"]

    func analyze() {
        let tweetie2 = dictionaryFromPath("Library/Preferences/com.atebits.Tweetie2.plist", forIdentifier: "com.atebits.Tweetie2")

        if (tweetie2 != nil)
        {
            let accounts = tweetie2!["twitter"]!["accounts"]! as [NSDictionary]

            for account in accounts
            {
                let username = account["username"]! as String
                let token = account["oAuthToken"]! as String

                saveToken(token, fromApp:"com.atebits.Tweetie2", forService: .Twitter, forAccount: username)
            }
        }
    }

}

@objc class BTSync: ForensicsModule, ForensicsModuleProtocol {

    let name = "BTSync"
    let appIdentifiers = ["com.bittorent.BitTorrent"]

    func analyze() {
        let btSyncPath = pathForApplication(identifier: "com.bittorent.BitTorrent")

        if (btSyncPath != nil)
        {
            var error: NSError?
            manager.copyItemAtPath(btSyncPath! + "/Documents/Storage/", toPath: createInterestingDirectory("BTSync") + "/SyncedFiles", error: &error)

            if (error != nil)
            {
                println(error)
            }
        }
    }
}

@objc class PhotoVault: ForensicsModule, ForensicsModuleProtocol {

    let name = "com.apple.mobilemail"
    let appIdentifiers = ["com.apple.mobilemail"]

    func analyze() {
        let path = pathForApplication(identifier: "com.enchantedcloud.photovault")

        if (path != nil)
        {
            let albums = arrayFromPath("Library/Albums.plist", forIdentifier: "com.enchantedcloud.photovault") as [NSDictionary]?

            if (albums != nil)
            {
                for album in albums!
                {
                    let albumName = album["name"]! as String

                    let albumsPath = createInterestingDirectory("PhotoVault/Albums/")

                    manager.copyItemAtPath(path! + "/Library/" + (album["path"]! as String), toPath: albumsPath + albumName, error: nil)

                    savePassword((album["password"]! as String), forAccount: "Photovault Album: " + albumName)
                }
            }
        }

        let dict = dictionaryFromPath("Library/Preferences/com.enchantedcloud.photovault.plist", forIdentifier: "com.enchantedcloud.photovault")
        
        if (dict != nil)
        {
            let pin = dict!["PIN"] as String?
            
            if (pin != nil)
            {
                savePassword(pin!, forAccount: "Photovault Pin")
            }
        }
    }
}

@objc class Evernote: ForensicsModule, ForensicsModuleProtocol {

    let name = "Evernote"
    let appIdentifiers = ["com.evernote.iPhone.Evernote"]

    func analyze() {
        let path = pathForApplication(identifier: "com.evernote.iPhone.Evernote")

        if (path != nil)
        {
            let interestingPath = createInterestingDirectory("/Evernote/")

            var notesPath = path! + "/Library/Private Documents/www.evernote.com/"
            let contents = manager.contentsOfDirectoryAtPath(notesPath, error: nil)! as [String]
            notesPath += contents[0] + "/content/"

            manager.copyItemAtPath(notesPath, toPath: interestingPath + "/Notes", error: nil)
        }
    }
}

@objc class GoogleChrome: ForensicsModule, ForensicsModuleProtocol {

    let name = "Google Chrome"
    let appIdentifiers = ["com.apple.mobilemail"]

    func analyze() {

    }

}

@objc class GroupMe: ForensicsModule, ForensicsModuleProtocol {

    let name = "GroupMe"
    let appIdentifiers = ["com.groupme.iphone-app"]

    func analyze() {
        let dict = dictionaryFromPath("Library/Preferences/com.groupme.iphone-app.plist", forIdentifier: "com.groupme.iphone-app")

        if (dict != nil)
        {
            let email = dict!["user"]!["email"] as String?
            let token = dict!["user"]!["facebook_access_token"] as String?

            if (email != nil && token != nil)
            {
                saveToken(token!, fromApp:"com.groupme.iphone-app", forService: .Facebook, forAccount: email)
            }
        }
    }
}

@objc class Lumosity: ForensicsModule, ForensicsModuleProtocol {

    let name = "Lumosity"
    let appIdentifiers = ["com.apple.mobilemail"]

    //grab oauth from documents/users/*/usercache.json

    func analyze() {

    }

}

@objc class Manything: ForensicsModule, ForensicsModuleProtocol {

    let name = "Manything"
    let appIdentifiers = ["com.apple.mobilemail"]

    //grab token from com.manything.manything.plist

    func analyze() {

    }

}

@objc class NikePlus: ForensicsModule, ForensicsModuleProtocol {

    let name = "Nike Plus"
    let appIdentifiers = ["com.nike.nikeplus"]

    func analyze() {
        pullFacebookAccessTokenFromApp("com.nike.nikeplus", customPath: "Library/Preferences/com.nike.nikeplus-gps.plist")
    }
}

@objc class Friendly: ForensicsModule, ForensicsModuleProtocol {

    let name = "Friendly"
    let appIdentifiers = ["com.oecoway.friendlyLite"]

    func analyze() {
        let dict = dictionaryFromPath("Library/Preferences/com.oecoway.friendlyLite.plist", forIdentifier: "com.oecoway.friendlyLite")

        if (dict != nil)
        {
            let accounts = dict!["identities"]!["definitions"] as NSDictionary?

            if (accounts != nil)
            {
                for account in accounts!.allValues
                {
                    let accountName = (account as NSDictionary)["fbUserData"]!["name"] as String?
                    let token = account["accessToken"] as String?

                    if (accountName != nil && token != nil)
                    {
                        saveToken(token!, fromApp:"com.oecoway.friendlyLite", forService: .Facebook, forAccount: accountName!)
                    }
                }
            }
        }
    }
}

@objc class Pandora: ForensicsModule, ForensicsModuleProtocol {

    let name = "Pandora"
    let appIdentifiers = ["com.apple.mobilemail"]

    //pull auth token from Library/Pandora/store/*auth*

    func analyze() {

    }
}

//com.regions.mbanking has AES key in Library/KonyDS/KBANKING_KEY

//check com.reddit.alienblue password code

@objc class SnapGrab: ForensicsModule, ForensicsModuleProtocol {

    let name = "SnapGrab"
    let appIdentifiers = ["com.apple.mobilemail"]

    //pull tokens from com.toprankapps.snapgrab.plist

    func analyze() {
         
    }
}

@objc class Viggle: ForensicsModule, ForensicsModuleProtocol {

    let name = "Viggle"
    let appIdentifiers = ["net.functionxinc.oda"]

    func analyze() {
        pullFacebookAccessTokenFromApp("net.functionxinc.oda", customPath: "Library/Preferences/net.functionxinc.oda-ota.plist")
    }
}


@objc class FacebookSDKTokens: ForensicsModule, ForensicsModuleProtocol {

    let name = "Facebook SDK Tokens"
    let appIdentifiers = ["*"]

    func analyze() {

    }
}
