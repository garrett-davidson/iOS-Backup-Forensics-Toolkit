//
//  ViewController.swift
//  iOS Backup Forensics Toolkit
//
//  Created by Garrett Davidson on 11/30/14.
//  Copyright (c) 2014 Garrett Davidson. All rights reserved.
//

import Cocoa

class ViewController: NSViewController {

    //For debugging only
    let shouldRecreateFileSystem = false

    let defaultManager = NSFileManager.defaultManager()

    var backupDirectory = ""
    var outputDirectory = ""

    @IBOutlet weak var backupDirectoryField: NSTextField!
    @IBOutlet weak var outputDirectoryField: NSTextField!

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
            outputDirectory = openPanel.URL!.path!
            outputDirectoryField.stringValue = outputDirectory
        }
    }

    @IBAction func startAnalyzing(sender: AnyObject) {

        //DEBUG
        if (self.shouldRecreateFileSystem)
        {
            analyzeInfoPlist()
            recreateFileSystem()
        }

        else
        {
            analyze()
        }
    }

    func analyze() {
        sectionLabel.stringValue = "Analyzing"

        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), {

            var outDir = self.outputDirectory
            //DEBUG
            if (!self.shouldRecreateFileSystem)
            {
                outDir += "/<Unknown>"
            }

            let investigator = Forensics(outputDirectory: outDir)

            investigator.beginAnalyzing()

            dispatch_async(dispatch_get_main_queue(), {
                self.sectionLabel.stringValue = "Finished"
            })
        })


    }

    func recreateFileSystem() {
        sectionLabel.stringValue = "Recreating file system"
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), {
            let manifest = MBDB(path: self.backupDirectory, outDirectory: self.outputDirectory)
            manifest.recreateFilesytem()
            dispatch_async(dispatch_get_main_queue(), {
                self.taskLabel.stringValue = "Finished recreating file system"
            })
            self.analyze()
        })
    }

    func analyzeInfoPlist() {
        sectionLabel.stringValue = "Copying Info.plist"

        taskLabel.stringValue = "Reading Info.plist"
        let path = backupDirectory + "/Info.plist"
        let info = NSDictionary(contentsOfFile: path)!
        outputDirectory += "/" + (info.objectForKey("Device Name") as String)

        //check if backup encrypted?
        //check isEncrypted in Manifest.plist

        var error: NSError?
        defaultManager.createDirectoryAtPath(outputDirectory, withIntermediateDirectories: true, attributes: nil, error: &error)
        defaultManager.copyItemAtPath(path, toPath: outputDirectory + "/Info.plist", error: &error)

        if (error != nil)
        {
            println(error)
        }
    }

}

