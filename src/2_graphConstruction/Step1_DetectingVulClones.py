
"""
Author:		Seunghoon Woo (seunghoonwoo@korea.ac.kr)
Modified: 	August 1, 2021.
"""

import os
import sys
import subprocess
import re
import tlsh # Please intall python-tlsh

"""GLOBALS"""

currentPath	= os.getcwd()
vulFuncPath = "../1_poolConstruction/CVEPool/vulFuncs/"
nvdVulPath  = "../1_poolConstruction/CVEPool/NVD_vulhashes"			# Default path
repoPath	= "../1_poolConstruction/SoftwarePool/repo_functions/"	# Default path
funcPath 	= "../1_poolConstruction/SoftwarePool/raw_functions/"	# Default path
cloneResPath = currentPath + "/clone_detection_res"
##############


def main():

	fres 	= open(cloneResPath, 'w')
	vulDict = {}

	# Read the collected vulnerability information
	with open(nvdVulPath, 'r', encoding = "UTF-8") as fp:
		body = ''.join(fp.readlines()).strip()
		for each in body.split('\n'):
			vulHash = each.split('\t')[0]
			vulInfo = each.split('\t')[1]
			vulDict[vulHash] = vulInfo


	for oss in os.listdir(repoPath):
		ossHashes = []

		for files in os.listdir(repoPath + oss):
			with open(repoPath + oss + '/' + files, 'r', encoding = "UTF-8") as fp:
				ver = files.split('fuzzy_')[1].split('.hidx')[0]
				body = ''.join(fp.readlines()).strip()

				for eachLine in body.split('\n')[1:]:
					functionHash = eachLine.split('\t')[0]
					functionPath = eachLine.split('\t')[1]

					if functionHash in vulDict:
						# Exact vulnerable clone
						CVE 	= vulDict[functionHash].split('_')[0]
						vulInfo = vulDict[functionHash]
						isModi 	= "E" # Exact clone
						
						printStr = CVE + '\t' + functionHash + '\t' + functionPath + '\t' + isModi + '\t' + vulInfo + '\t' + oss + '\t' + ver
						fres.write(printStr + '\n')

					else:
						for eachVulHash in vulDict:
							
							score = tlsh.diffxlen(functionHash, eachVulHash)

							if int(score) <= 30:
								delLines = []
								addLines = []
								rawFunc  = []

								try:
									with open(vulFuncPath + vulDict[eachVulHash].replace('OLD.vul', 'DELLINES.vul'), 'r', encoding = "UTF-8") as fdel:
										delBody = ''.join(fdel)
										for eachDel in delBody.split('\n'):
											if eachDel.strip() != '':
												delLines.append(eachDel[1:].lstrip()) # For removing the first "-" character

									with open(vulFuncPath + vulDict[eachVulHash].replace('OLD.vul', 'INSLINES.vul'), 'r', encoding = "UTF-8") as fadd:
										addBody = ''.join(fadd)
										for eachAdd in addBody.split('\n'):
											if eachAdd.strip() != '':
												addLines.append(eachAdd[1:].lstrip()) # For removing the first "+" character

									with open(funcPath + oss + '/' + functionHash, 'r', encoding = "UTF-8") as fr:
										rawBody = ''.join(fr)
										for eachRaw in rawBody.split('\n'):
											rawFunc.append(eachRaw.lstrip())
								except:
									print ("No file error..")
									continue

								delFlag = 0
								addFlag = 0

								for eachDel in delLines:
									if eachDel not in rawFunc:
										delFlag = 1

								for eachAdd in addLines:
									if eachAdd in rawFunc:
										addFlag = 1

								if delFlag == 0 and addFlag == 0:
									# Modified vulnerable clone
									CVE 	= vulDict[eachVulHash].split('_')[0]
									vulInfo = '_'.join(vulDict[eachVulHash].split('_')[4:])
									isModi 	= "M"
									printStr = CVE + '\t' + functionHash + '\t' + functionPath + '\t' + isModi + '\t' + vulInfo + '\t' + oss + '\t' + ver
									fres.write(printStr + '\n')
	fres.close()


""" EXECUTE """
if __name__ == "__main__":
	main()