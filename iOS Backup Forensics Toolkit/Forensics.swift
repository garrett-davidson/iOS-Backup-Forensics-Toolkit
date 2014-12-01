//
//  Forensics.swift
//  iOS Backup Forensics Toolkit
//
//  Created by Garrett Davidson on 12/1/14.
//  Copyright (c) 2014 Garrett Davidson. All rights reserved.
//

import Foundation

class Forensics {
    let outputDirectory: String
    let manager = NSFileManager.defaultManager()

    var oauthTokens = Dictionary<String, [String]>()

    init(outputDirectory: String) {
        self.outputDirectory = outputDirectory
    }

    func beginAnalyzing() {
        memrise()
    }

    func memrise() {
        let path = pathForApplication(identifier: "com.memrise.ios.memrisecompanion")

        let dictPath = path + "/Preferences/com.memrise.ios.memrisecompanion.plist"
        if (manager.fileExistsAtPath(dictPath)) {
            let dict = NSDictionary(contentsOfFile: dictPath)!

        }
    }

    func pathForApplication(#identifier: String) -> String {
        let path = "\(outputDirectory)/Original/\(identifier)"

        if (manager.fileExistsAtPath(path)) {
            return path
        }

        else
        {
            return ""
        }
    }
}