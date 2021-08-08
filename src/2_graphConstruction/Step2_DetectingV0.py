
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
metaPath	= "../1_poolConstruction/SoftwarePool/meta_files/"		# Default path
cloneResPath = currentPath + "/clone_detection_res"
##############


def findingV0(cveDict, key):
	already = []
	srcdesPair = []

	for target in cveDict[key]:
		for comp in cveDict[key]:
			if target == comp:
				continue
			if target.split("@#@")[-2] == comp.split("@#@")[-2]:
				continue
			else:
				if target + comp not in already and comp + target not in already:
					already.append(target + comp)
					
					src = ""
					dst = ""


					tarHash, tarPath, tarOSS, tarVer = target.split('@#@')
					comHash, comPath, comOSS, comVer = comp.split('@#@')

					try:
						#tarHashes = {}
						#comHashes = {}

						tarHash_lst = []
						comHash_lst = []

						with open(repoPath + tarOSS + '/fuzzy_' + tarVer + '.hidx', 'r', encoding = "UTF-8") as ft:
							tarBody = ''.join(ft.readlines()[1:]).strip()
							for eachTarLine in tarBody.split('\n'):
								#tarHashes[eachTarLine.split('\t')[0]] = eachTarLine.split('\t')[1]
								tarHash_lst.append(eachTarLine.split('\t')[0])

						with open(repoPath + comOSS + '/fuzzy_' + comVer + '.hidx', 'r', encoding = "UTF-8") as ft:
							comBody = ''.join(ft.readlines()[1:]).strip()
							for eachComLine in comBody.split('\n'):
								#comHashes[eachComLine.split('\t')[0]] = eachComLine.split('\t')[1]
								comHash_lst.append(eachComLine.split('\t')[0])


						tarHash_lst = set(tarHash_lst)
						comHash_lst = set(comHash_lst)

						if tarHash_lst == comHash_lst: 
							continue

						if tarHash_lst in comHash_lst: # Shared code ratio-based identification.
							src = tarOSS
							des = comOSS
							srcdesPair.append(src + '@#@' + des)
						elif comHash_lst in tarHash_lst:
							src = comOSS
							des = tarOSS
							srcdesPair.append(src + '@#@' + des)

						elif tarPath != comPath: # Source code location-based identification.
							#print (tarPath, comPath)
							tarPath = tarPath.lower()
							comPath = comPath.lower()

							if tarPath in comPath:
								src = tarOSS
								des = comOSS
								srcdesPair.append(src + '@#@' + des)
							elif comPath in tarPath:
								src = comOSS
								des = tarOSS
								srcdesPair.append(src + '@#@' + des)

						else: # Metadata file-based identification.
							tarRoot = []
							comRoot = []
							tarNoroot = []
							comNoroot = []

							for tarMetas in os.listdir(metaPath + tarOSS):
								if "[" + tarVer + "]" in tarMetas and "[ROOT]" in tarMetas:
									with open(metaPath + tarOSS + '/' + tarMeats, 'r', encoding = "UTF-8") as tm:
										tarMetaBody = ''.join(tm.readlines()).strip()
										tarRoot.append(tarMetaBody)
								elif "[" + tarVer + "]" in tarMetas and "[NOROOT]" in tarMetas:
									with open(metaPath + tarOSS + '/' + tarMeats, 'r', encoding = "UTF-8") as tm:
										tarMetaBody = ''.join(tm.readlines()).strip()
										tarNoroot.append(tarMetaBody)

							for comMetas in os.listdir(metaPath + comOSS):
								if "[" + comVer + "]" in comMetas and "[ROOT]" in comMetas:
									with open(metaPath + comOSS + '/' + comMeats, 'r', encoding = "UTF-8") as cm:
										comMetaBody = ''.join(cm.readlines()).strip()
										comRoot.append(comMetaBody)
								elif "[" + comVer + "]" in comMetas and "[NOROOT]" in comMetas:
									with open(metaPath + comOSS + '/' + comMeats, 'r', encoding = "UTF-8") as cm:
										comMetaBody = ''.join(cm.readlines()).strip()
										comNoroot.append(comMetaBody)

							for eachTarRoot in tarRoot:
								if eachTarRoot in comNoroot and eachTarRoot not in comRoot:
									src = tarOSS
									des = comOSS
									srcdesPair.append(src + '@#@' + des)
									break

							for eachComRoot in comRoot:
								if eachComRoot in tarNoroot and eachComRoot not in tarRoot:
									src = comOSS
									des = tarOSS
									srcdesPair.append(src + '@#@' + des)
									break

					except:
						print ("parsing error..")

	srcdesPair = set(srcdesPair)

	v0_candi = []

	for eachValue in srcdesPair:
		src, des = eachValue.split('@#@')
		
		if src not in v0_candi:
			v0_candi.append(src)

		if des in v0_candi:
			v0_candi.remove(des)

	return key, v0_candi


def main():
	cveDict = {}

	with open(cloneResPath, 'r', encoding = "UTF-8") as fp:
		body = ''.join(fp.readlines()).strip()
		for each in body.split('\n'):
			cve, hashval, hashpath, modi, vulpath, oss, ver = each.split('\t')

			key = cve + "@#@" + vulpath #delimeter @#@
			val = hashval + "@#@" + hashpath + "@#@" + oss + "@#@" + ver

			if key not in cveDict:
				cveDict[key] = []

			cveDict[key].append(val)

	for key in cveDict:
		cve, v0 = findingV0(cveDict, key)
		print ("The V0(s) of " + cve + " is (are) " + str(v0))
		

""" EXECUTE """
if __name__ == "__main__":
	main()