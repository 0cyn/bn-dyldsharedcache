# Dyld Shared Cache Parser
Author: **cynder (kat)**

_Dyld Shared Cache Support for BinaryNinja. Built on DyldExtractor_

![BinaryNinja Screenshot](.github/sbui.png?raw=true "Screenshot")

Without any of the fuss of requiring manually loading several unrelated images, or the awful off-image addresses, and with better output than IDA, Hopper, or any other disassembler on the market. 

## Installation + Usage

**IMPORTANT: Once it has finished loading in the data, swap the View (top left drop-down selector) to MachO!**

1. Install capstone via pip for the same python interpreter your BinaryNinja install is using. 
2. git clone (or download and unzip) this folder to your BinaryNinja plugins folder.

### Usage:

1. Open Dyld Shared Cache file with BN
2. Select the Image you would like to disassemble
3. Wait for the Image to be loaded in
4. Once you see the prompt to change Views, swap the View type (in the top left corner of the main View) from "DyldCacheExtractor" to Mach-O. 
5. Congrats, you are now reversing the image as if it were a regular Mach-O! :)

## Description:

This project acts as an interface for two seperate projects; DyldExtractor, and ktool. Mainly DyldExtractor.

[DyldExtractor](https://github.com/arandomdev/DyldExtractor) is a project written primarily by 'arandomdev' designed for CLI standalone dyld_shared_cache extraction. It is *the* best tool for the job, and reverses the majority of "optimizations" that make DSC reverse engineering ugly and painful. Utilizing this plugin, Binja's processing should outperform IDAs, and wont require IDA's need for repeatedly right clicking and manually loading tons of modules.

This version of DyldExtractor has a lot of modifications (read: a lot of commented out lines) from the original designed to make it function better in the binja environment. 

[ktool](https://github.com/cxnder/ktool) is a multifaceted project I wrote for, primarily, MachO + ObjC Parsing.

I use it here because we store DyldExtractor's output in a BytesIO object, which ktool can handle and parse as if it's a valid MachO; and also because ktool is designed to work very well with DyldExtractor output. 

It is mainly used for super basic parsing of the output, as we need to properly write the segments to the VM (and scrap all the dsc data that was originally in this file) so the Mach-O View knows how to parse it. 

## License

This plugin, along with ktool and dyldextractor are released under an [MIT license](./license). Both of these plugins are vendored within this project to make installation slightly simpler. 
