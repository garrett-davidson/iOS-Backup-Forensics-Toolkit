//
//  Forensics.swift
//  iOS Backup Forensics Toolkit
//
//  Created by Garrett Davidson on 12/1/14.
//  Copyright (c) 2014 Garrett Davidson. All rights reserved.
//

import Foundation

class Forensics {
    let originalDirectory: String
    let interestingDirectory: String

    let manager = NSFileManager.defaultManager()

    var oauthTokens = Dictionary<String, Dictionary<String, Dictionary<String, [String]>>>()

    var emailAccounts = [String]()

    var passwords = Dictionary<String, String>()

    enum Services: String {
        case Facebook = "Facebook"
        case Twitter = "Twitter"
    }

    init(outputDirectory: String) {
        self.originalDirectory = outputDirectory + "/Original/"
        self.interestingDirectory = outputDirectory + "/Interesting/"
    }

    func beginAnalyzing() {
        manager.createDirectoryAtPath(interestingDirectory, withIntermediateDirectories: false, attributes: nil, error: nil)


        memrise()
        mobileMail()
        mobileSafari()
        twitter()
        btSync()
        peak()
        delta()
        duolingo()
        photovault()
        evernote()
        googleChrome()
        groupMe()
        jamstar()
        lumosity()
        manything()
        anyCodes()
        nikePlus()
        friendly()
        pandora()
        fitocracy()
        roomSurfU()
        heartRateLite()
        libra()
        runtasticPullupLite()
        runtasticPushupLite()
        runtasticSixPackLite()
        spotify()
        snapGrab()
        viggle()



        finishAnalyzing()
    }

    func viggle() {
        pullFacebookAccessTokenFromApp("net.functionxinc.oda", customPath: "Library/Preferences/net.functionxinc.oda-ota.plist")
    }

    func snapGrab() {
        //pull tokens from com.toprankapps.snapgrab.plist
    }

    func spotify() {
        pullFacebookAccessTokenFromApp("com.spotify.client")
    }

    func runtasticSixPackLite() {
        pullFacebookAccessTokenFromApp("com.runtastic.iphone.sixpack.lite")
    }

    func runtasticPushupLite() {
        pullFacebookAccessTokenFromApp("com.runtastic.iphone.pushup.lite")
    }

    func runtasticPullupLite() {
        pullFacebookAccessTokenFromApp("com.runtastic.iphone.pullup.lite")
    }

    func libra() {
        pullFacebookAccessTokenFromApp("com.runtastic.iphone.libra.lite")
    }

    func heartRateLite() {
        pullFacebookAccessTokenFromApp("com.runtastic.iphone.heartrate.lite")
    }

    func roomSurfU() {
        pullFacebookAccessTokenFromApp("com.roomsurf.joinu")
    }

    func fitocracy() {
        pullFacebookAccessTokenFromApp("com.release.fitocracy")
    }

    //com.regions.mbanking has AES key in Library/KonyDS/KBANKING_KEY

    //check com.reddit.alienblue password code

    func pandora() {
        //pull auth token from Library/Pandora/store/*auth*

        pullFacebookAccessTokenFromApp("com.pandora")
    }

    func friendly() {
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

    func nikePlus() {
        pullFacebookAccessTokenFromApp("com.nike.nikeplus", customPath: "Library/Preferences/com.nike.nikeplus-gps.plist")
    }

    func anyCodes() {
        pullFacebookAccessTokenFromApp("com.mega.mega.AnyCodesN")
    }

    func manything() {
        //grab token from com.manything.manything.plist
    }

    func lumosity() {
        //grab ouath from documents/users/*/usercache.json
    }

    func jamstar() {
        pullFacebookAccessTokenFromApp("com.Jamstar.iOS")
    }

    func groupMe() {
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

    func googleChrome() {

    }

    func evernote() {
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

    func photovault() {
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

    func duolingo() {
        pullFacebookAccessTokenFromApp("com.duolingo.DuolingoMobile")
    }

    func delta() {
        pullFacebookAccessTokenFromApp("com.delta.iphone.ver1")
    }

    func peak() {
        pullFacebookAccessTokenFromApp("com.brainbow.peakprod")
    }

    func btSync() {
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

    func twitter() {
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

    func mobileSafari() {

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

            NSDictionary(dictionary: tabs).writeToFile(interestingDirectory + "/Safari/open-tabs.plist", atomically: true)

            let privateBrowsing = suspendedState!["SafariStatePrivateDocuments"] as [NSDictionary]?

            if (privateBrowsing != nil)
            {
                var privateTabs = Dictionary<String, String>()

                for tab in privateBrowsing!
                {
                    privateTabs[(tab["SafariStateDocumentTitle"]! as String)] = (tab["SafariStateDocumentUserVisibleURL"]! as String)
                }

                NSDictionary(dictionary: privateTabs).writeToFile(interestingDirectory + "/Safari/open-private-tabs.plist", atomically: true)
            }
        }

        //Local storage
        let safariPath = pathForApplication(identifier: "com.apple.mobilesafari")
        if (safariPath != nil)
        {
            manager.copyItemAtPath(safariPath! + "/Library/WebKit/WebsiteData/LocalStorage/", toPath: interestingDirectory + "/Safari/LocalStorage", error: nil)
        }
    }


    func mobileMail() {

//        let emailsDict = dictionaryFromPath("Library/Preferences/com.apple.MailAccount-ExtProperties.plist", forIdentifier: "com.apple.mobilemail")
//
//        if (emailsDict != nil)
//        {
//
//        }

        var vips = Dictionary<String, [String]>()
        let vipDict = dictionaryFromPath("Library/Preferences/com.apple.mobilemail.plist", forIdentifier: "com.apple.mobilemail")

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

    func memrise() {
        pullFacebookAccessTokenFromApp("com.memrise.ios.memrisecompanion")
    }

    func finishAnalyzing() {
        //Is there a way to do this without creating a new NSDictionary?

        if (oauthTokens.count > 0)
        {
            NSDictionary(dictionary: oauthTokens).writeToFile(interestingDirectory + "oauthTokens.plist", atomically: true)
        }

        if (passwords.count > 0)
        {
            NSDictionary(dictionary: passwords).writeToFile(interestingDirectory + "passwords.plist", atomically: true)
        }
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
        passwords[account] = password
    }
}