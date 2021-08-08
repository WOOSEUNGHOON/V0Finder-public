# V0Finder 
V0Finder is an approach for detecting correct origin information of public software vulnerabilities.
Principles and experimental results are discussed in our paper, which will be published in 30th USENIX Security Symposium (Security 2021).

※ Exception handling parts may be insufficient due to many modifications in the code refactoring process; we will improve them.

## How to use
### Requirements

#### Software
* ***Linux***: V0Finder is designed to work on any of the operating systems. However, currently, this repository only focuses on the Linux environment.
* ***Git***
* ***Python 3***
* ***[Universal-ctags](https://github.com/universal-ctags/ctags)***: for function parsing.
* ***[Python3-tlsh](https://pypi.org/project/python-tlsh/)***: for function hashing.

How to install Python3-tlsh:

```
sudo apt-get install python3-pip
sudo pip3 install py-tlsh
```

Our utilized versions: Python 3.9.1, python3-tlsh 4.5.0, and universal-ctags p5.9.20201227.0 on Ubuntu 18.04.

#### Hardware
* We recommend a minimum of 32 GB RAM to utilize a large amount of OSS datasets in graph construction.
##

### Running V0Finder

※ If you have problems related to path information, try testing with absolute paths.

### Pool Construction (src/1_poolConstruction/)

#### 1. CVE Pool construction (src/1_poolConstruction/CVEPool)
 - Download NVD JSON Feeds (downloaded [here](https://nvd.nist.gov/vuln/data-feeds)) and store all the json file at "src/1_poolConstruction/CVEPool/NVDjsonfeed/" (the stored JSON feeds are samples collected in March 2021).
 - Specify the directory paths in [CVEPatch_Collector.py](https://github.com/WOOSEUNGHOON/V0Finder-dev/blob/main/src/1_poolConstruction/CVEPool/CVEPatch_Collector.py) (line 15 to 34), where CVE diffs and corresponding vulnerable functions will be stored. 
 - Execute [CVEPatch_Collector.py](https://github.com/WOOSEUNGHOON/V0Finder-dev/blob/main/src/1_poolConstruction/CVEPool/CVEPatch_Collector.py) (several warnings may occur due to encoding issues).
 ```
 python3 OCVEPatch_Collector.py
 ```
 - Check the outputs (description based on the default paths).
   * ***./diffs/***: Directory for storing collected CVE Diffs;
   * ***./clones/***: Directory for storing source codes of cloned repositories (reported one or more CVEs);
   * ***./vulFuncs/***: Directory for storing extracted vulnerable functions (with code lines added/deleted from the corresponding patch) from all diffs;
   * ***./NVD_vulhashes***: The output file where the hash values of the vulnerable functions are stored.

#### 2. Software Pool construction (src/1_poolConstruction/SoftwarePool)
 - Collect git clone URLs into a single file, as shown in the [sample file](https://github.com/WOOSEUNGHOON/V0Finder-dev/blob/main/src/1_poolConstruction/SoftwarePool/sample).
 - Specify the directory paths in [OSS_Collector.py](https://github.com/WOOSEUNGHOON/V0Finder-dev/blob/main/src/1_poolConstruction/SoftwarePool/OSS_Collector.py) (line 17 to 24), where cloned repositories and their functions will be stored. Also you should specify the path of the installed ctags here.
 - Execute [OSS_Collector.py](https://github.com/WOOSEUNGHOON/V0Finder-dev/blob/main/src/1_poolConstruction/SoftwarePool/OSS_Collector.py) (several warnings may occur due to encoding issues).
 ```
 python3 OSS_Collector.py
 ```
 - Check the outputs (description based on the default paths).
   * ***./repo_src/***: Directory for storing source codes of collected repositories;
   * ***./repo_date/***: Directory for storing release dates of every version of all collected repositories;
   * ***./raw_functions/***: Directory for storing all extracted functions from all collected repositories;
   * ***./repo_functions/***: Directory for storing hashed extracted functions from all collected repositories.
   * ***./meta_files/***: Directory for storing metadata files (i.e., README, COPYING, and LICENSE files) from all collected repositories.

### Graph Construction (src/2_graphConstruction/)

#### 1. Detecting vulnerable clones (src/2_graphConstruction/Step1_DetectingVulClones.py)
 - Specify the directory paths in [Step1_DetectingVulClones.py](https://github.com/WOOSEUNGHOON/V0Finder-dev/blob/main/src/2_graphConstruction/Step1_DetectingVulClones.py) (line 15 to 20); these should be matched the output path of CVEPool and SoftwarePool.
 - Execute [Step1_DetectingVulClones.py](https://github.com/WOOSEUNGHOON/V0Finder-dev/blob/main/src/2_graphConstruction/Step1_DetectingVulClones.py) (several warnings may occur due to encoding issues).
 ```
 python3 Step1_DetectingVulClones.py
 ```
 - Check the outputs (description based on the default paths).
   * ***./clone_detection_res***: A file that stores vulnerable clone detection results. The schema of each line in the file is as follow (delimited by tabs)
     * CVE ID
     * Vulnerable function hash value
     * Vulnerable function path in the OSS
     * Modification status
     * Vulnerable function information
     * Detected OSS
     * Version information
      
#### 2. Detecting V0 for each vulnerability (src/2_graphConstruction/Step2_DetectingV0.py)
 - Specify the directory paths in [Step2_DetectingV0.py](https://github.com/WOOSEUNGHOON/V0Finder-dev/blob/main/src/2_graphConstruction/Step2_DetectingV0.py) (line 15 to 21); these should be matched the output path of CVEPool and SoftwarePool.
 - Execute [Step2_DetectingV0.py](https://github.com/WOOSEUNGHOON/V0Finder-dev/blob/main/src/2_graphConstruction/Step2_DetectingV0.py).
 ```
 python3 Step2_DetectingV0.py
 ```
 - As a result, V0 for each CVE is printed.

### About
This repository is authored and maintained by Seunghoon Woo.
For reporting bugs, you can submit an issue to [the GitHub repository](https://github.com/WOOSEUNGHOON/V0Finder-public) or send me an email (<seunghoonwoo@korea.ac.kr>).
