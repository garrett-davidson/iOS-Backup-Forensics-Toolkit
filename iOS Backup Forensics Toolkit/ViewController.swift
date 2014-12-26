//
//  ViewController.swift
//  iOS Backup Forensics Toolkit
//
//  Created by Garrett Davidson on 11/30/14.
//  Copyright (c) 2014 Garrett Davidson. All rights reserved.
//

import Foundation
import Cocoa
import AppKit
import ForensicsModuleFramework

class ViewController: NSViewController {

    let manager = NSFileManager.defaultManager()

    var backupDirectory = ViewController.ClassVariables.debugging ? "/Users/garrettdavidson/GenTest/Downloads/untitled folder 2/MobileSync/\(ClassVariables.debuggingDeviceName)" : ""
    var originalDirectory = ViewController.ClassVariables.debugging ? "/Users/garrettdavidson/GenTest/Downloads/untitled folder 2/MobileSync/\(ClassVariables.debuggingDeviceName)/Original/" : ""
    var interestingDirectory = ViewController.ClassVariables.debugging ? "/Users/garrettdavidson/GenTest/Downloads/untitled folder 2/MobileSync/\(ClassVariables.debuggingDeviceName)/Interesting/" :""
    var bundleDirectory = ViewController.ClassVariables.debugging ? "/Users/garrettdavidson/Library/Developer/Xcode/DerivedData/iOS_Backup_Forensics_Toolkit-affiakrgssjgszenwbnxcrvjadvs/Build/Products/Debug/" : ""

    struct ClassVariables
    {
        static var modules = [ForensicsModuleProtocol]()
        static var oauthTokens = Dictionary<String, Dictionary<String, Dictionary<String, [String]>>>()
        static var passwords = Dictionary<String, String>()
        static let debugging = true
        static let debuggingDeviceName = "<Unknown>"
    }

    @IBOutlet weak var backupDirectoryField: NSTextField!
    @IBOutlet weak var outputDirectoryField: NSTextField!
    @IBOutlet weak var bundleDirectoryField: NSTextField!

    @IBOutlet weak var sectionLabel: NSTextField!
    @IBOutlet weak var taskLabel: NSTextField!

    
    override func viewDidLoad() {
        super.viewDidLoad()

        // Do any additional setup after loading the view.
    }

    override var representedObject: AnyObject? {
        didSet {
        // Update the view, if already loaded.
        }
    }

    @IBAction func selectBackupLocation(sender: AnyObject) {
        let openPanel = NSOpenPanel()
        openPanel.directoryURL = NSURL(string: NSHomeDirectory() + "/Library/Application Support/MobileSync/Backup")
        openPanel.canChooseDirectories = true
        openPanel.canChooseFiles = false
        if (openPanel.runModal() == NSOKButton) {
            backupDirectory = openPanel.URL!.path!
            backupDirectoryField.stringValue = backupDirectory
        }
    }

    @IBAction func selectOutputLocation(sender: AnyObject) {
        let openPanel = NSOpenPanel()
        openPanel.canChooseDirectories = true
        openPanel.canChooseFiles = false
        if (openPanel.runModal() == NSOKButton) {
            originalDirectory = openPanel.URL!.path!
            outputDirectoryField.stringValue = originalDirectory
        }
    }

    @IBAction func selectBundleLocation(sender: AnyObject) {
        let openPanel = NSOpenPanel()
        openPanel.canChooseDirectories = true
        openPanel.canChooseFiles = false
        if (openPanel.runModal() == NSOKButton) {
            bundleDirectory = openPanel.URL!.path!
            bundleDirectoryField.stringValue = bundleDirectory
        }
    }
    @IBAction func startAnalyzing(sender: AnyObject) {

        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
        {

            if (!ViewController.ClassVariables.debugging)
            {
                self.analyzeInfoPlist()
                self.recreateFileSystem()
            }

            else
            {
                self.analyze()
            }

        })
    }

    func loadBundles() {
        let bundles = retrieveBundles(NSBundle.mainBundle().builtInPlugInsPath!) + retrieveBundles(bundleDirectory)

        for bundle in bundles {
            if let bundleClass: AnyClass = bundle.principalClass
            {
                ViewController.ClassVariables.modules += bundleClass.loadBundleWithDirectories(originalDirectory: originalDirectory, interestingDirectory: interestingDirectory).modules
            }
        }
    }

    func retrieveBundles(path: String) -> [NSBundle] {
        let bundleDirectoryPaths = path == "" ? [String]() : manager.contentsOfDirectoryAtPath(path, error: nil) as [String]

        var bundles = [NSBundle]()
        for bundlePath in bundleDirectoryPaths
        {
            if (bundlePath.rangeOfString(".bundle") != nil)
            {
                let loadedBundle = NSBundle(path: path + "/" + bundlePath)!

                //for some reason this causes a segmentation fault when using ForensicsBundleProtocol.Protocol
//                if let bundleClass = loadedBundle.principalClass as? ForensicsBundleProtocol.Protocol
                
                bundles.append(loadedBundle)
            }
        }

        dispatch_async(dispatch_get_main_queue(),
        {
//            self.performSegueWithIdentifier("listModules", sender: self)
//            MainViewController.ClassVariables.modules = [ForensicsModuleProtocol]()
        })


        return bundles
    }

    func analyze() {
        self.loadBundles()
        dispatch_async(dispatch_get_main_queue(),
        {
            self.sectionLabel.stringValue = "Analyzing"
        })

        self.manager.createDirectoryAtPath(self.interestingDirectory, withIntermediateDirectories: false, attributes: nil, error: nil)

        self.beginAnalyzing()

        dispatch_async(dispatch_get_main_queue(), {
            self.sectionLabel.stringValue = "Finished"
            self.taskLabel.stringValue = ""
        })
    }

    func beginAnalyzing() {
        //run all loaded modules

        dispatch_async(dispatch_get_main_queue(),
        {
            self.sectionLabel.stringValue = "Analyzing"
        })

        for module in ViewController.ClassVariables.modules
        {
            dispatch_async(dispatch_get_main_queue(),
            {
                self.taskLabel.stringValue = module.name
            })
            module.analyze()
        }


        finishAnalyzing()
    }

    func finishAnalyzing() {
        //Is there a way to do this without creating a new NSDictionary?


        for module in ViewController.ClassVariables.modules {

            //pull oauthTokens from modules
            for site in module.oauthTokens.keys {
                for user in module.oauthTokens[site]!.keys {
                    for (identifier, identifierValues) in module.oauthTokens[site]![user]! {
                        if (ClassVariables.oauthTokens[site] == nil) {
                            ClassVariables.oauthTokens[site] = Dictionary<String, Dictionary<String, [String]>>()
                        }
                        if (ClassVariables.oauthTokens[site]![user] == nil) {
                            ClassVariables.oauthTokens[site]![user] = Dictionary<String, [String]>()
                        }

                        if (ClassVariables.oauthTokens[site]![user]![identifier] == nil) {
                            ClassVariables.oauthTokens[site]![user]![identifier] = identifierValues
                        }

                        else {
                            ClassVariables.oauthTokens[site]![user]![identifier]! += identifierValues
                        }
                    }
                }
            }

            //pull passwords from modules
            //TODO: check for overwriting
            for (account, password) in module.passwords {
                ClassVariables.passwords[account] = password
            }
        }

        if (ClassVariables.oauthTokens.count > 0)
        {
            NSDictionary(dictionary: ClassVariables.oauthTokens).writeToFile(interestingDirectory + "oauthTokens.plist", atomically: true)
        }

        if (ClassVariables.passwords.count > 0)
        {
            NSDictionary(dictionary: ClassVariables.passwords).writeToFile(interestingDirectory + "passwords.plist", atomically: true)
        }
    }

    func recreateFileSystem() {
        dispatch_async(dispatch_get_main_queue(),
        {
            self.sectionLabel.stringValue = "Recreating file system"
        })

        self.taskLabel.stringValue = "Copying files"
        let manifest = MBDB(path: self.backupDirectory, outDirectory: self.originalDirectory)
        manifest.recreateFilesytem()
        dispatch_async(dispatch_get_main_queue(), {
            self.taskLabel.stringValue = "Finished recreating file system"
        })
        self.analyze()
    }

    func analyzeInfoPlist() {
        //TODO: catch no info.plist error
        sectionLabel.stringValue = "Copying Info.plist"

        taskLabel.stringValue = "Reading Info.plist"
        let path = backupDirectory + "/Info.plist"
        let info = NSDictionary(contentsOfFile: path)!
        let rootDirectory = originalDirectory + "/" + (info.objectForKey("Device Name") as String)
        originalDirectory = rootDirectory + "/Original/"
        interestingDirectory = rootDirectory + "/Interesting/"

        //check if backup encrypted?
        //check isEncrypted in Manifest.plist

        var error: NSError?
        manager.createDirectoryAtPath(originalDirectory, withIntermediateDirectories: true, attributes: nil, error: &error)
        manager.createDirectoryAtPath(interestingDirectory, withIntermediateDirectories: true, attributes: nil, error: &error)
        manager.copyItemAtPath(path, toPath: rootDirectory + "/Info.plist", error: &error)

        if (error != nil)
        {
            println(error)
        }
    }

}

class ModuleSelectionViewController: NSViewController, NSTableViewDelegate, NSTableViewDataSource {

    var modules = [ForensicsModuleProtocol]()
    var selected = [Bool]()

    override func viewDidLoad() {
        let modules = ViewController.ClassVariables.modules as [ForensicsModuleProtocol]?

        if (modules != nil)
        {
            self.modules = modules!
            selected = [Bool](count: modules!.count, repeatedValue: true)
        }

        ViewController.ClassVariables.modules = [ForensicsModuleProtocol]()
    }
    func numberOfRowsInTableView(aTableView: NSTableView) -> Int {
        return modules.count
    }

    enum Attributes: String {
        case Use = "Use"
        case Name = "Name"
        case Bundle = "Bundle"
        case Identifiers = "Identifiers"
        case Descritpion = "Description"
    }

    func tableView(tableView: NSTableView, objectValueForTableColumn column: NSTableColumn?, row: Int) -> AnyObject? {
        switch (column!.identifier) {

            case "Use":
                return selected[row]

            case "Name":
                return modules[row].name

            case "Bundle":
                return modules[row].bundle.name

            case "Identifiers":
                var returnString = ""
                let identifiers = modules[row].appIdentifiers
                for i in 0...identifiers.count
                {
                    if (i != 0) { returnString += ", " }
                    returnString += identifiers[i]
                }
                return returnString

            case "Description":
                return modules[row].description()

            default:
                return nil
        }
    }

    func tableView(tableView: NSTableView, setObjectValue value: AnyObject?, forTableColumn column: NSTableColumn?, row: Int) {
        if (column!.identifier == "Use")
        {
            selected[row] = value! as Bool
        }
    }
    @IBAction func okButton(sender: AnyObject) {
        var selectedModules = [ForensicsModuleProtocol]()
        for i in 0...modules.count
        {
            if (selected[i])
            {
                selectedModules.append(modules[i])
            }
        }

        ViewController.ClassVariables.modules = selectedModules
    }
}

