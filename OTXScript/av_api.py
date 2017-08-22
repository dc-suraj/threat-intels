#!/usr/bin/python
import requests, re, time, json
from OTXv2 import OTXv2
import IndicatorTypes
import get_malicious

'''
###########################################################################
Uses: 
av_feed = av.domain('rigotechnology.com')
###########################################################################
'''

#OTX Information
otx_server = 'https://otx.alienvault.com/'
api_key = "a67d30eac6fcab93e83ba286ce00f8c0e6350ae510f60acfe45cdf2dd1c4a819"
otx = OTXv2(api_key, server=otx_server)
file_name="otx_intel.txt"
header_chk="#fields indicator indicator_type meta.source meta.url meta.do_notice"
try:
	file_chk=open(file_name,"r")
	first_line=file_chk.readline().strip()
	file_chk.close()
	if first_line!=header_chk:
		file_chk=open(file_name,"w")
		header_chk=header_chk+"\n"
		file_chk.write(header_chk)
		file_chk.close()
except:
	file_chk=open(file_name,"w")
	header_chk=header_chk+"\n"
	file_chk.write(header_chk)
	file_chk.close()
	
class av_api(object):
	def __parse_domain(self, domain_result):
		#result = {}
		result=""
		source= "https://www.threatcrowd.org/domain.php?domain="
		try:
			result = result+ domain_result['general']['indicator']
		except:
			result = result+ '-'
			
		result= result + " Intel::DOMAIN"
		source= source + domain_result['general']['indicator']
		result= result + " Alienvault-OTX " + source
		result= result + " F\n" 
		'''try:
			result['otx_url'] = domain_result['malware']['next']
		except:
			result['otx_url']='NA'
		try:
			result['url'] = domain_result['url_list']['url_list'][0]['url']
		except:
			result['url'] = 'NA'
		try:
			result['ip'] = domain_result['url_list']['url_list'][0]['result']['urlworker']['ip']
		except:
			result['ip'] = 'NA'
		
		try:
			count = domain_result['general']['pulse_info']['count']
			i = 0
		
			for pulse_id in domain_result['general']['pulse_info']['pulses']:
				pulses= pulse_id['id']
				pulse_name = pulse_id['name']
				result['pulse_description_'+str(i)] = {"id":pulses, "name": pulse_name}
				i +=1
				
		except:
			result['pulse_description'] = "NA"
		try:
			result['references'] = domain_result['general']['pulse_info']['references']
		except:
			print "no ref"'''
		file = open(file_name, 'a')
		file.write(result)
		file.close()
		print result
		return result

	def __parse_ip(self, ip_result):
		#result = {}
		result=""
		source= "https://www.threatcrowd.org/ip.php?ip="
		try:
			result= result + ip_result['general']['indicator']
		except:
			result = result +'-'
		result= result + " Intel::ADDR"
		source= source + ip_result['general']['indicator']
		result= result + " Alienvault-OTX " + source
		result= result + " F\n" 
		'''try:
			result= ip_result['malware']['next']
		except:
			result['otx_url']='NA'
		try:
			result['url'] = ip_result['url_list']['url_list'][0]['url']
		except:
			result['url'] = 'NA'
		try:
			result['ip'] = ip_result['url_list']['url_list'][0]['result']['urlworker']['ip']
		except:
			result['ip'] = 'NA'
		
		try:
			count = ip_result['general']['pulse_info']['count']
			i = 0
		
			for pulse_id in ip_result['general']['pulse_info']['pulses']:
				pulses= pulse_id['id']
				pulse_name = pulse_id['name']
				result['pulse_description_'+str(i)] = {"id":pulses, "name": pulse_name}
				i +=1
				
		except:
			result['pulse_description'] = "NA"
		try:
			result['references'] = ip_result['general']['pulse_info']['references']
		except:
			print "no ref"'''
		file = open(file_name, 'a')
		file.write(result)
		file.close()
		print result
		return result

#Functions for searching ip/domain/hash
	def av_ip(self, search_string):
		ip_result = get_malicious.ip(otx, search_string)
		if len(ip_result) > 0:
			ip_result = otx.get_indicator_details_full(IndicatorTypes.IPv4, search_string)
			return self.__parse_ip(ip_result)
		else:
			pass
	
	def av_domain(self, search_string):
		domain_result = get_malicious.hostname(otx, search_string)
		if len(domain_result) > 0:
			domain_result = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, search_string)
			'''
			file = open('domain3.json', 'w')
			file.write(json.dumps(domain_result))
			file.close()
			'''
			return self.__parse_domain(domain_result)
		else:
			pass

	
		
	def av_hash(self, search_string):
		hash_result =  get_malicious.file(otx, search_string)
   		if len(hash_result) > 0:
   			hash_result = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5, search_string)
   			return self.__parse_hash(hash_result)
   		else:
   			pass
		
