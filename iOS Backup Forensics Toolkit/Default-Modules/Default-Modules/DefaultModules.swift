//
//  DefaultModules.swift
//  iOS Backup Forensics Toolkit
//
//  Created by Garrett Davidson on 12/3/14.
//  Copyright (c) 2014 Garrett Davidson. All rights reserved.
//

import Foundation
import ForensicsModuleFramework

class DefaultModulesBundle: ForensicsBundleProtocol {
    @objc let name = "Default"
    @objc let originalDirectory: String
    @objc let interestingDirectory: String
    @objc var modules: [ForensicsModuleProtocol] = [ForensicsModuleProtocol]()

    @objc class func loadBundleWithDirectories(#originalDirectory: String, interestingDirectory: String) -> ForensicsBundleProtocol {
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
            FacebookSDKTokens(bundle: bundle),
            SMSAttachments(bundle: bundle),
            Accounts(bundle: bundle),
            Contacts(bundle: bundle),
            Calendar(bundle: bundle),
            PhoneRecords(bundle: bundle),
            HiddenPhoto(bundle: bundle),
            Tumblr(bundle: bundle),
            Skype(bundle: bundle),
            Instagram(bundle: bundle),
            Viber(bundle: bundle),
            InstaCrop(bundle: bundle),
            VoiceRecordings(bundle: bundle)
        ]

        return bundle
    }

    init(originalDirectory: String, interestingDirectory: String) {
        self.originalDirectory = originalDirectory
        self.interestingDirectory = interestingDirectory
    }

}

//Facebook from HomeDomain
//Get full name, fb email, fb profile link

//Check Candy Crush for fb oauth

//try snapchat with tokens

class InstaCrop: ForensicsModule, ForensicsModuleProtocol {
    let name = "InstaCrop"
    let appIdentifiers = ["com.six8t.InstaCropFree"]

    func analyze() {
        let appPath = pathForApplication(identifier: "com.six8t.InstaCropFree")

        if (appPath != nil)
        {
            let interestingPath = bundle.interestingDirectory + "/InstaCrop"
            manager.createDirectoryAtPath(interestingPath, withIntermediateDirectories: false, attributes: nil, error: nil)
            manager.copyItemAtPath(appPath! + "/Documents", toPath: interestingPath + "/Documents", error: nil)
        }
    }
}

class Viber: ForensicsModule, ForensicsModuleProtocol {
    let name = "Viber"
    let appIdentifiers = ["com.viber"]

    func analyze() {
        //sqlite pull contact
    }
}

class Instagram: ForensicsModule, ForensicsModuleProtocol {
    let name = "Instagram"
    let appIdentifiers = ["com.burbn.instagram"]

    func analyze() {
        let appPath = pathForApplication(identifier: "com.burbn.instagram")

        if (appPath != nil)
        {
            let interestingPath = bundle.interestingDirectory + "/Instagram"
            manager.createDirectoryAtPath(interestingPath, withIntermediateDirectories: false, attributes: nil, error: nil)
            manager.copyItemAtPath(appPath! + "/Documents/Inbox/", toPath: interestingPath + "/Inbox", error: nil)
        }
    }
}

class Skype: ForensicsModule, ForensicsModuleProtocol {
    let name = "Skype"
    let appIdentifiers = ["com.skype.SkypeForiPad"]

    func analyze() {
        let appPath = pathForApplication(identifier: "com.skype.SkypeForiPad")
        let dict = dictionaryFromPath("Library/Preferences/com.skype.SkypeForiPad", forIdentifier: "com.skype.SkypeForiPad")

        if (dict != nil)
        {
            let username = dict!["SkypePrefsLastLoggedInSkypeName"] as! String
            let fullName = dict!["SkypePrefsLastLoggedInFullName"] as! String
            
            let xmlPath = "\(appPath)/Library/Application Support/Skype/\(username)/config.xml"

            let credentials3 = pullXMLValue(xmlPath, tag: "Credentials3")
            let token = pullXMLValue(xmlPath, tag: "Token")

            //pull sqlite stuff
            //Username
            //Real name
            //Profile picture
            //Emails
            //Call history
            //Chat history
            //Contacts
            //SMS
            //Voicemails
        }
    }
}

class Tumblr: ForensicsModule, ForensicsModuleProtocol {
    let name = "Tumblr"
    let appIdentifiers = ["com.tumblr.tumblr"]

    func analyze() {
        let dict = dictionaryFromPath("Library/Preferences/com.tumblr.tumblr.plist", forIdentifier: "com.tumblr.tumblr")

        if (dict != nil)
        {
            for account in (dict!["UserDefaultAccountsInfo"] as! Dictionary<String, NSDictionary>).keys {
                saveToken(((dict!["UserDefaultAccountsInfo"]![account]! as! NSDictionary)["OAuthToken"]! as! String), fromApp: "com.tumblr.tumblr", forService: .Tumblr, forAccount: account)
            }
        }
    }
}

class HiddenPhoto: ForensicsModule, ForensicsModuleProtocol {
    let name = "Private Photo (Calculator%)"
    let appIdentifiers = ["com.aromdee.HiddenPhoto"]

    func analyze() {
        let hiddenPhotoPath = pathForApplication(identifier: "com.aromdee.HiddenPhoto")
        if (hiddenPhotoPath != nil)
        {
            manager.createDirectoryAtPath(bundle.interestingDirectory + "/Private Photo", withIntermediateDirectories: false, attributes: nil, error: nil)
            manager.copyItemAtPath(hiddenPhotoPath! + "/Documents/Album", toPath: bundle.interestingDirectory + "/Private Photo/Album", error: nil)
        }
    }
}

class VoiceRecordings: ForensicsModule, ForensicsModuleProtocol {
    let name = "Voice Recordings"
    let appIdentifiers = ["N/A"]

    func analyze() {
        let path = bundle.originalDirectory + "MediaDomain/Media/Recordings/"
        let outputPath = bundle.interestingDirectory + "Voice Recordings/"

        let files = manager.contentsOfDirectoryAtPath(path, error: nil) as? [String]

        if (files != nil)
        {
            for file in files!
            {
                if (file.rangeOfString(".m4a") != nil)
                {
                    if (!manager.fileExistsAtPath(outputPath))
                    {
                        manager.createDirectoryAtPath(outputPath, withIntermediateDirectories: false, attributes: nil, error: nil)
                        manager.copyItemAtPath(path + "AssetManifest.plist", toPath: outputPath + "AssetManifest.plist", error: nil)
                    }

                    manager.copyItemAtPath(path + file, toPath: outputPath + file, error: nil)
                }
            }
        }
    }
}
//Voice recordings from MediaDomain/Media/Recordings

//Keychain

//Voicemail from HomeDomain

//Text messages from HomeDomain

//Safari Bookmarks from HomeDomain

//Notes from HomeDomain

//Recent emails from HomeDomain

//Cookies from HomeDomain


class PhoneRecords: ForensicsModule, ForensicsModuleProtocol {
    let name = "Phone Records"
    let appIdentifiers = ["???"] //find phone identifier

    func analyze() {
        let path = bundle.interestingDirectory + "/Phone Records/"
        manager.createDirectoryAtPath(path, withIntermediateDirectories: false, attributes: nil, error: nil)
        manager.copyItemAtPath(bundle.originalDirectory + "/HomeDomain/Library/CallHistoryDB/CallHistory.storedata", toPath: path + "CallHistory.sqlite", error: nil)
    }
}

class Calendar: ForensicsModule, ForensicsModuleProtocol {
    let name = "Calendar"
    let appIdentifiers = ["???"] //find calender identifier

    func analyze() {
        manager.copyItemAtPath(bundle.originalDirectory + "/HomeDomain/Library/Calendar", toPath: bundle.interestingDirectory + "/Calendar", error: nil)
    }
}

class Contacts: ForensicsModule, ForensicsModuleProtocol {
    let name = "Contacts"
    let appIdentifiers = ["???"] //find contacts identifier

    func analyze() {
        manager.copyItemAtPath(bundle.originalDirectory + "/HomeDomain/Library/AddressBook/", toPath: bundle.interestingDirectory + "/Contacts/", error: nil)
    }
}

class Accounts: ForensicsModule, ForensicsModuleProtocol {
    let name = "Accounts"
    let appIdentifiers = ["N/A"]

    func analyze() {
        manager.copyItemAtPath(bundle.originalDirectory + "/HomeDomain/Library/Accounts/", toPath: bundle.interestingDirectory + "/Accounts", error: nil)
    }
}

class SMSAttachments: ForensicsModule, ForensicsModuleProtocol {
    let name = "SMS Attachments"
    let appIdentifiers = ["???"] //find messages identifier

    func analyze() {
        manager.copyItemAtPath(bundle.originalDirectory + "/MediaDomain/Library/SMS/Attachments/", toPath: bundle.interestingDirectory + "/SMS Attachments/", error: nil)
    }
}

//Camera roll
//Photostreams

class MobileMail: ForensicsModule, ForensicsModuleProtocol {

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
            let vipArray = vipDict!["VIP-senders"] as! Dictionary<String, NSDictionary>?

            if (vipArray != nil)
            {

                for vip in vipArray!.values
                {
                    vips[(vip["n"]! as! String)] = (vip["a"]! as! [String])
                }
                
                NSDictionary(dictionary: vips).writeToFile(createInterestingDirectory("Mail") + "/VIPs.plist", atomically: true)
            }
        }
    }

}

class MobileSafari: ForensicsModule, ForensicsModuleProtocol {

    let name = "Mobile Safari"
    let appIdentifiers = ["com.apple.mobilesafari"]

    func analyze() {
        //Recent searches
        let mobileSafari = dictionaryFromPath("Library/Preferences/com.apple.mobilesafari.plist", forIdentifier: "com.apple.mobilesafari")
        if (mobileSafari != nil)
        {
            var recentSearches = mobileSafari!["RecentWebSearches"] as! NSArray?

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

            let regularBrowsing = suspendedState!["SafariStateDocuments"]! as! [NSDictionary]
            var tabs = Dictionary<String, String>()

            for tab in regularBrowsing
            {
                tabs[(tab["SafariStateDocumentTitle"]! as! String)] = (tab["SafariStateDocumentUserVisibleURL"]! as! String)
            }

            NSDictionary(dictionary: tabs).writeToFile(bundle.interestingDirectory + "/Safari/open-tabs.plist", atomically: true)

            let privateBrowsing = suspendedState!["SafariStatePrivateDocuments"] as! [NSDictionary]?

            if (privateBrowsing != nil)
            {
                var privateTabs = Dictionary<String, String>()

                for tab in privateBrowsing!
                {
                    privateTabs[(tab["SafariStateDocumentTitle"]! as! String)] = (tab["SafariStateDocumentUserVisibleURL"]! as! String)
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

class Twitter: ForensicsModule, ForensicsModuleProtocol {

    let name = "Twitter"
    let appIdentifiers = ["com.atebits.Tweetie2"]

    func analyze() {
        let tweetie2 = dictionaryFromPath("Library/Preferences/com.atebits.Tweetie2.plist", forIdentifier: "com.atebits.Tweetie2")

        if (tweetie2 != nil)
        {
            let accounts = tweetie2!["twitter"]!["accounts"]! as! [NSDictionary]

            for account in accounts
            {
                let username = account["username"]! as! String
                let token = account["oAuthToken"]! as! String

                saveToken(token, fromApp:"com.atebits.Tweetie2", forService: .Twitter, forAccount: username)
            }
        }
    }

}

class BTSync: ForensicsModule, ForensicsModuleProtocol {

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

class PhotoVault: ForensicsModule, ForensicsModuleProtocol {

    let name = "PhotoVault"
    let appIdentifiers = ["com.enchantedcloud.photovault"]

    func analyze() {
        let path = pathForApplication(identifier: "com.enchantedcloud.photovault")

        if (path != nil)
        {
            let albums = arrayFromPath("Library/Albums.plist", forIdentifier: "com.enchantedcloud.photovault") as! [NSDictionary]?

            if (albums != nil)
            {
                for album in albums!
                {
                    let albumName = album["name"]! as! String

                    let albumsPath = createInterestingDirectory("PhotoVault/Albums/")

                    manager.copyItemAtPath(path! + "/Library/" + (album["path"]! as! String), toPath: albumsPath + albumName, error: nil)

                    if let password = (album["password"] as? String)
                    {
                        savePassword(password, forAccount: "Photovault Album: " + albumName)
                    }
                }
            }
        }

        let dict = dictionaryFromPath("Library/Preferences/com.enchantedcloud.photovault.plist", forIdentifier: "com.enchantedcloud.photovault")
        
        if (dict != nil)
        {
            let pin = dict!["PIN"] as! String?
            
            if (pin != nil)
            {
                savePassword(pin!, forAccount: "Photovault Pin")
            }
        }
    }
}

class Evernote: ForensicsModule, ForensicsModuleProtocol {

    let name = "Evernote"
    let appIdentifiers = ["com.evernote.iPhone.Evernote"]

    func analyze() {
        let path = pathForApplication(identifier: "com.evernote.iPhone.Evernote")

        if (path != nil)
        {
            let interestingPath = createInterestingDirectory("/Evernote/")

            var notesPath = path! + "/Library/Private Documents/www.evernote.com/"
            let contents = manager.contentsOfDirectoryAtPath(notesPath, error: nil)! as! [String]
            notesPath += contents[0] + "/content/"

            manager.copyItemAtPath(notesPath, toPath: interestingPath + "/Notes", error: nil)
        }
    }
}

class GoogleChrome: ForensicsModule, ForensicsModuleProtocol {

    let name = "Google Chrome"
    let appIdentifiers = ["com.apple.mobilemail"]

    func analyze() {

    }

}

class GroupMe: ForensicsModule, ForensicsModuleProtocol {

    let name = "GroupMe"
    let appIdentifiers = ["com.groupme.iphone-app"]

    func analyze() {
        let dict = dictionaryFromPath("Library/Preferences/com.groupme.iphone-app.plist", forIdentifier: "com.groupme.iphone-app")

        if (dict != nil)
        {
            let email = dict!["user"]!["email"] as! String?
            let token = dict!["user"]!["facebook_access_token"] as! String?

            if (email != nil && token != nil)
            {
                saveToken(token!, fromApp:"com.groupme.iphone-app", forService: .Facebook, forAccount: email)
            }
        }
    }
}

class Lumosity: ForensicsModule, ForensicsModuleProtocol {

    let name = "Lumosity"
    let appIdentifiers = ["com.apple.mobilemail"]

    //TODO
    //grab oauth from documents/users/*/usercache.json

    func analyze() {

    }

}

class Manything: ForensicsModule, ForensicsModuleProtocol {

    let name = "Manything"
    let appIdentifiers = ["com.apple.mobilemail"]

    //TODO
    //grab token from com.manything.manything.plist

    func analyze() {

    }

}

class NikePlus: ForensicsModule, ForensicsModuleProtocol {

    let name = "Nike Plus"
    let appIdentifiers = ["com.nike.nikeplus"]

    func analyze() {
        pullFacebookAccessTokenFromApp(identifier: "com.nike.nikeplus", customPath: "Library/Preferences/com.nike.nikeplus-gps.plist")
    }
}

class Friendly: ForensicsModule, ForensicsModuleProtocol {

    let name = "Friendly"
    let appIdentifiers = ["com.oecoway.friendlyLite"]

    func analyze() {
        let dict = dictionaryFromPath("Library/Preferences/com.oecoway.friendlyLite.plist", forIdentifier: "com.oecoway.friendlyLite")

        if (dict != nil)
        {
            let accounts = dict!["identities"]!["definitions"] as! NSDictionary?

            if (accounts != nil)
            {
                for account in accounts!.allValues
                {
                    let accountName = (account as! NSDictionary)["fbUserData"]!["name"] as! String?
                    let token = account["accessToken"] as? String?

                    if (accountName != nil && token != nil)
                    {
                        saveToken(token!!, fromApp:"com.oecoway.friendlyLite", forService: .Facebook, forAccount: accountName!)
                    }
                }
            }
        }
    }
}

class Pandora: ForensicsModule, ForensicsModuleProtocol {

    let name = "Pandora"
    let appIdentifiers = ["com.pandora"]

    //TODO
    //pull auth token from Library/Pandora/store/*auth*

    func analyze() {

    }
}

//TODO
//com.regions.mbanking has AES key in Library/KonyDS/KBANKING_KEY

//TODO
//check com.reddit.alienblue password code

class SnapGrab: ForensicsModule, ForensicsModuleProtocol {

    let name = "SnapGrab"
    let appIdentifiers = ["com.apple.mobilemail"]

    //pull tokens from com.toprankapps.snapgrab.plist

    func analyze() {
         
    }
}

class Viggle: ForensicsModule, ForensicsModuleProtocol {

    let name = "Viggle"
    let appIdentifiers = ["net.functionxinc.oda"]

    func analyze() {
        pullFacebookAccessTokenFromApp(identifier: "net.functionxinc.oda", customPath: "Library/Preferences/net.functionxinc.oda-ota.plist")
    }
}


class FacebookSDKTokens: ForensicsModule, ForensicsModuleProtocol {

    let name = "Facebook SDK Tokens"
    let appIdentifiers = ["*"]

    func analyze() {
        let apps = manager.contentsOfDirectoryAtPath(bundle.originalDirectory + "/Applications/", error: nil) as? [String]
        if (apps != nil)
        {
            for app in apps! {
                pullFacebookAccessTokenFromApp(identifier: app)
            }
        }
    }
}
