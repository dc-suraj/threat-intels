#!/usr/bin/python
import requests, json

#URL
bad_ip = "https://badips.com/get/info/"

class badips(object):
	def __parse_results(self, json_result):
		result = {}
		try:
			result['Listed'] = json_result.get('Listed')
		except:
			result['Listed'] = 'NA'
		try:
			result['Categories'] = json_result.get('Categories')
		except:
			result['Categories'] = 'NA'
		try:
			result['Scores'] = json_result.get('Score')
		except:
			result['Scores'] = 'NA'
		try:
			result['IP'] = json_result.get('IP')
		except:
			result['IP'] = 'NA'
		return result

	def bad_ip(self, search_string):
		#print "ready"
		json_result = requests.get(bad_ip +'%(search_string)s' %{'search_string':search_string}, timeout=30).json()
		return self.__parse_results(json_result)
	

	