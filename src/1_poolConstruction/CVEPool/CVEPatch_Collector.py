import os
import subprocess
import json
import sys
from bs4 import BeautifulSoup
import urllib.request
import urllib.parse
import time
import random
import re
import tlsh


## CONFIGURE ##
jsonpath 	= './NVDjsonfeed'
gitlist 	= [
	"github.com",
	"cgit",
	"gitlab",
	"gitweb"
]
homePath 	= os.getcwd()
diffPath	= homePath + "/diffs/"
clonePath	= homePath + "/clones/"
vulFuncPath = homePath + "/vulFuncs/"
ctagPath	= homePath + "/ctags"		# Ctags binary path (please specify your own ctags path)

# Generate directories
shouldMake = [diffPath, clonePath, vulFuncPath]
for eachRepo in shouldMake:
	if not os.path.isdir(eachRepo):
		os.mkdir(eachRepo)

vf = open(homePath + '/NVD_vulhashes', 'w')

URLS = {}
META = {}
###############




def compute_tlsh(string):
	hs = tlsh.forcehash(string)
	return hs

def removeComment(string):
	# Code for removing C/C++ style comments. (Imported from ReDeBug.)
	c_regex = re.compile(
		r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
		re.DOTALL | re.MULTILINE)
	return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])

def normalize(string):
	# Code for normalizing the input string.
	# LF and TAB literals, curly braces, and spaces are removed,
	# and all characters are lowercased.
	return ''.join(string.replace('\n', '').replace('\r', '').replace('\t', '').replace('{', '').replace('}', '').split(
		' ')).lower()
	
def cloningRepo(pack, clone):
	if os.path.isdir(clonePath + pack):
		return
	if not clone.startswith('git clone'):
		clone = 'git clone ' + clone
	elif clone.startswith('git clonegit'):
		clone = clone.replace('git clonegit', 'git clone git')

	try:
		print ('[-] Now parsing ' + pack + '..')
		result = subprocess.check_output(clone + ' ' + clonePath + pack, stderr=subprocess.STDOUT, shell=True)
	except subprocess.CalledProcessError as e:
		print (e)

def getPackageName(url):
	# Heuristics..

	pack 	= ""
	clone	= ""

	if 'github.com' in url and 'commit' in url:
		pack 	= url.split('github.com/')[1].split('/')[0]+'##'+url.split('github.com/')[1].split('/')[1]
		clone 	= 'git clone https://github.com/'+pack.replace('##','/')+'.git'

	elif 'gitlab' in url and 'commit' in url:
		if 'gitlab.com/' in url:
			pack 	= url.split('gitlab.com/')[1].split('/')[0]+'##'+url.split('gitlab.com/')[1].split('/')[1]
			clone 	= 'git clone https://gitlab.com/'+pack.replace('##','/')+'.git'
			
		else:
			if '.org' in url:
				pack 	= url.split('commit')[0].split('.org/')[1].split('/')[0]+'##'+url.split('commit')[0].split('.org/')[1].split('/')[1]
				clone 	= 'git clone https://gitlab.com/'+pack.replace('##','/')+'.git'
								
			else:
				pack	= url.split('commit')[0].split('/')[-3]+'##'+url.split('commit')[0].split('/')[-2]
				clone 	= 'git clone https://gitlab.com/'+pack.replace('##','/')+'.git'
				

	elif 'cgit' in url and 'commit' in url:
		try:
			will_be_parsed 	= url.split('commit')[0]
			soup 			= BeautifulSoup(urllib.request.urlopen(will_be_parsed).read(), 'html.parser')

			for eachline in str(soup.text).split('\n'):
				if 'git://' in eachline:
					if not eachline.startswith('git://'):
						continue
					else:
						clone 	= 'git clone' + eachline
						pack 	= eachline.split('/')[-2]+'##'+eachline.split('/')[-1].replace('.git', '')

		except:
			pass

	elif 'gitweb' in url and 'commit' in url:
		if '?p=' in url:
			if 'gitweb' not in url.split('/')[2]:
				pack 	= 'gitweb##'+url.split('?p=')[1].split(';')[0].replace('.git', '')
				clone	= 'git://'+url.split('/')[2].split('gitweb')[0]+'/'+url.split('?p=')[1].split(';')[0]

	return pack, clone






def main():
	for jsonfile in os.listdir(jsonpath):
		with open(os.path.join(jsonpath, jsonfile), 'r', encoding = "UTF-8") as fp:
			res     = json.load(fp)
			cvelist = res["CVE_Items"]

			for eachcve in cvelist:
				isPatch 	= 0
				CVEID 		= "CVE-0000-0000"
				CWEID 		= "CWE-000"
				CVSSv2 		= 0.0

				CVEID  	 	= eachcve["cve"]["CVE_data_meta"]["ID"]

				try:
					CWEID   = eachcve["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
				except:
					CWEID 	= "CWE-000"

				try:
					CVSSv2  = eachcve["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
				except:
					CVSSv2 	= 0.0

				refs    	= eachcve["cve"]["references"]["reference_data"]

				META[CVEID] = CVEID+'_'+CWEID+'_'+str(CVSSv2)

				for eachref in refs:
					url = eachref["url"]

					for keyword in gitlist:
						if keyword in url.lower():
							if 'commit' not in url:
								continue
							if META[CVEID] not in URLS:
								URLS[META[CVEID]] = []
							URLS[META[CVEID]].append(url)

	print ('[+] Done: Parsing Git-related URLs from the NVD JSON feeds.')


	for CVE in URLS:
		for url in URLS[CVE]:
			pack, clone = getPackageName(url)
			
			##For later vul-Funcs parsing##
			if pack == "gitweb##linux/kernel/git/torvalds/linux-2.6":
				pack = "torvalds##linux"
			###############################

			will_be_parsed = ""

			if 'github.com' in url and 'commit' in url:
				will_be_parsed = url + '.diff'
			elif 'gitlab' in url and 'commit' in url:
				will_be_parsed = url + '.diff'
			elif 'cgit' in url and 'commit' in url:
				will_be_parsed = url.replace('/commit/', '/patch/')
			elif 'gitweb' in url and 'commit' in url:
				will_be_parsed = url.replace('a=commit', 'a=commitdiff_plain')
			else:
				pass


			try:
				soup 		= BeautifulSoup(urllib.request.urlopen(will_be_parsed).read(), 'html.parser')
				idx 		= 0 
				#Some CVEs have multiple diffs
				save_file 	= CVE.split('\t')[0] + '_' + str(idx) + '.diff'

				while True:
					if save_file in os.listdir(diffPath):
						save_file 	= save_file.replace(str(idx) + '.diff', str(idx + 1) + '.diff')
						idx 		+= 1
					else:
						break

				# We only consider C/C++ related patches
				diffBody = soup.text

				meta 	= diffBody.split('diff --git a')[0]
				saveStr = meta+'\n'
				flag 	= 0


				for chunks in diffBody.split('diff --git a')[1:]:
					ext = chunks.split('\n')[0]
					if ext.endswith('.c') or ext.endswith('.cc') or ext.endswith('.cpp'):
						saveStr += "diff --git a" + chunks + '\n'
						flag 	= 1

				if flag == 1:
					fs = open(diffPath + save_file, 'w')
					fs.write("PACK:" + pack + '\n')
					fs.write("CLONE:" + clone + '\n')
					fs.write("URL:" + url + '\n')
					fs.write(saveStr)
					fs.close()

					cloningRepo(pack, clone)

			except:
				pass


	for diffs in os.listdir(diffPath):
		os.chdir(homePath)

		with open(os.path.join(diffPath, diffs), 'r', encoding = "UTF-8") as fd:
			body   		= ''.join(fd.readlines())
			splitedBody = body.split('\n')

			if 'PACK:' not in splitedBody[0] or 'CLONE:' not in splitedBody[1] or 'URL:' not in splitedBody[2]:
			   continue

			pack 	= body.split('\n')[0].split('PACK:')[1]
			if pack =='':
				print (diffs + '\t' + ": this vul. cannot be parsed automatically..")
				continue

			clone 	= body.split('\n')[1].split('CLONE:')[1]
			url  	= body.split('\n')[2].split('URL:')[1]
			os.chdir(clonePath + pack)

			for chunk in body.split('diff --git ')[1:]:
				first_chunk 	= chunk.split('\n')[0]
				second_chunk 	= chunk.split('\n')[1]

				if 'index ' not in second_chunk or '..' not in second_chunk:
					continue

				#==#
				oldPath = first_chunk.split(' b/')[0]
				oldIdx  = second_chunk.split('index ')[1].split('..')[0]
				#==#
				newPath = 'b/'+first_chunk.split(' b/')[1]
				newIdx  = second_chunk.split('..')[1].split(' ')[0]
				#==#

				finer = chunk.split('@@')

				sl = 0
				el = 0
				
				delLines = []
				insLines = []

				for i in range(1, len(finer), 2):
					try:
						sl = int(finer[i].split(' -')[1].split(',')[0])
						el = sl + int(finer[i].split(' +')[0].split(',')[1])
					except:
						print ("line parsing error..")
						continue
					
					for patchLine in finer[i+1].split('\n'):
						if patchLine.startswith("-") and not patchLine.startswith("--"):
							delLines.append(patchLine)
						elif patchLine.startswith("+") and not patchLine.startswith("++"):
							insLines.append(patchLine)
					
					vulfile = "vulfile." + oldPath.split('.')[-1]
					command = "git show " + oldIdx + " > " + vulfile
					#print (pack, command, diffs)

					try:
						res = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
															
						finding_cfiles = subprocess.check_output(ctagPath + ' --fields=+ne -o - --sort=no ' + vulfile, stderr=subprocess.STDOUT, shell=True).decode(errors='ignore')

						alllist = str(finding_cfiles)
						with open(vulfile, 'r') as fp:
							body = ''.join(fp.readlines())

							for result in alllist.split('\n'):
								if result == '' or result == ' ' or result == '\n':
									continue

								filepath = result.split('\t')[1]
								funcname = result.split('\t')[0]
								if len(result.split('\t')) < 7:
									continue

								if result.split('\t')[3] =='f' and 'function:' not in result.split('\t')[5] and 'function:' not in result.split('\t')[6]:
									startline = int(result.split('\t')[4].replace('line:', ''))
									endline = int(result.split('\t')[-1].replace('end:', ''))
									if sl >= startline and el <= endline:
										funcbody = ''.join(''.join('\n'.join(body.split('\n')[startline-1: endline]).split('{')[1:]).split('}')[:-1])
										
										funcPath = diffs.split('.diff')[0] + '_' + pack + '_' + oldPath.split('/')[-1] + '@@' + funcname + '_OLD.vul'
										delPath  = diffs.split('.diff')[0] + '_' + pack + '_' + oldPath.split('/')[-1] + '@@' + funcname + '_DELLINES.vul'
										insPath  = diffs.split('.diff')[0] + '_' + pack + '_' + oldPath.split('/')[-1] + '@@' + funcname + '_INSLINES.vul'

										f = open(vulFuncPath + funcPath, 'w')
										f.write(funcbody)
										f.close()

										fdel = open(vulFuncPath + delPath, 'w')
										for dels in delLines:
											fdel.write(dels + '\n')
										fdel.close()

										fins = open(vulFuncPath + insPath, 'w')
										for ins in insLines:
											fins.write(ins + '\n')
										fins.close()

										funcbody = removeComment(funcbody)
										funcbody = normalize(funcbody)
										fuzzyhash = compute_tlsh(funcbody.encode())
										
										if len(fuzzyhash) == 72 and fuzzyhash.startswith("T1"):
											fuzzyhash = fuzzyhash[2:]
										elif fuzzyhash == "TNULL" or fuzzyhash == "" or fuzzyhash == "NULL":
											continue

										vf.write(fuzzyhash + '\t' + funcPath + '\n')

					except subprocess.CalledProcessError as e:
						print (e)
					except:
						print ('func parsing error..')

	vf.close()


""" EXECUTE """
if __name__ == "__main__":
	main()
