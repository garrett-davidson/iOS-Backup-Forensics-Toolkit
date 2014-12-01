//
//  ViewController.swift
//  iOS Backup Forensics Toolkit
//
//  Created by Garrett Davidson on 11/30/14.
//  Copyright (c) 2014 Garrett Davidson. All rights reserved.
//

import Cocoa

class ViewController: NSViewController {

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
//        analyzeInfoPlist()
//        recreateFileSystem()
        analyze()
    }

    func analyze() {
        sectionLabel.stringValue = "Analyzing"

        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), {
            //DEBUG
            let investigator = Forensics(outputDirectory: self.outputDirectory + "/<Unknown>")


//            let investigator = Forensics(outputDirectory: self.outputDirectory)

            investigator.beginAnalyzing()
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

