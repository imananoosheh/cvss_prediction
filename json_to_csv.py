import json
import sys
import os

file_location_2018 = os.path.join(os.getcwd(), "data", "nvdcve-1.0-2018.json")

jsonfile = open(file_location_2018)
cve_data = json.loads(jsonfile.read())

jsonfile.close()


with open('train_data_cpe.tsv', 'a') as train_data_file_heading:
	train_data_file_heading.write('primary_id' + "\t" + 'CVE_Id' + "\t" + 'description' + "\t" + 'confi_impact' + "\t" + 'integrity_impact' + "\t" + 'availability_impact' + "\t" + 'base_severity' + '\t' + 'vendor_name' + '\t' + 'product_name' + '\t' + '# of versions' + '\t' + 'cwe' + '\t' + 'cpe_a' + '\t' + 'cpe_o' + '\t' + 'cpe_h' + '\t' + 'target_column' + '\n')


def write_to_csv(string_1, dictionary, cwe, cpe_part, target_column):
	cpe_a = '0'
	cpe_o = '0'
	cpe_h = '0'

	if('a' in cpe_part):
		cpe_a = str(1)
	if('o' in cpe_part):
		cpe_o = str(1)
	if('h' in cpe_part):
		cpe_h = str(1)

	with open('train_data_cpe.tsv', 'a') as train_data_file:
		for key, string_2 in dictionary.items():
			train_data_file.write(str(key) + '\t' +string_1 + '\t' + string_2 + '\t' + cwe + '\t' + cpe_a + '\t' + cpe_o + '\t' + cpe_h + '\t' + str(target_column) + '\n')

primary_id = 0
dict_index = 0

for cve_items in cve_data['CVE_Items']:
	flat = {}
	#dict_index = 0

	url_1 = url_2 = description = attack_vector = attack_complexity = privileges_required = user_interaction = scope = confi_impact = integrity_impact = availability_impact = base_score = base_severity = exploitability_score = impact_score = ''	
	
	keys_cve_items = cve_items.keys()
	
	CVE_Id = cve_items['cve']['CVE_data_meta']['ID']
	
	try:
		url_1 = cve_items['cve']['references']['reference_data'][0]['url']
	except IndexError:
		url_1 = ''

	try:
		url_2 = cve_items['cve']['references']['reference_data'][1]['url']
	except IndexError:
		url_2 = ''
		
	description = cve_items['cve']['description']['description_data'][0]['value']

	if(len(cve_items['impact']) != 0):
		attack_vector = cve_items['impact']['baseMetricV3']['cvssV3']['attackVector']
		attack_complexity = cve_items['impact']['baseMetricV3']['cvssV3']['attackComplexity']
		privileges_required = cve_items['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
		user_interaction = cve_items['impact']['baseMetricV3']['cvssV3']['userInteraction']
		scope = cve_items['impact']['baseMetricV3']['cvssV3']['scope']
		confi_impact = cve_items['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
		integrity_impact = cve_items['impact']['baseMetricV3']['cvssV3']['integrityImpact']
		availability_impact = cve_items['impact']['baseMetricV3']['cvssV3']['availabilityImpact']
		base_score = cve_items['impact']['baseMetricV3']['cvssV3']['baseScore']
		base_severity = cve_items['impact']['baseMetricV3']['cvssV3']['baseSeverity']
		exploitability_score = cve_items['impact']['baseMetricV3']['exploitabilityScore']
		impact_score = cve_items['impact']['baseMetricV3']['impactScore']

	for vendor_data in cve_items['cve']['affects']['vendor']['vendor_data']:
		#primary_id = primary_id + 1
		flat_list = []
		vendor_name = vendor_data['vendor_name']

		for products in vendor_data['product']['product_data']:
			new_string = ''
			dict_index = dict_index + 1
			product_name = products['product_name']
			no_of_versions = len(products['version']['version_data'])
			new_string = vendor_name + '\t' + product_name + '\t' + str(no_of_versions)
			flat[dict_index] = new_string
			
	'''		
	first_part = CVE_Id + "\t" + attack_vector + "\t" + attack_complexity + "\t" + privileges_required + "\t" + user_interaction + "\t" + scope + "\t" + confi_impact + "\t" + integrity_impact + "\t" + availability_impact + "\t" + str(base_score) + "\t" + base_severity + "\t" + str(exploitability_score) + "\t" + str(impact_score)
	'''
	
	all_parts = set()
	for nodes in cve_items['configurations']['nodes']:
		if('cpe_match' in nodes):
			for cpe_match in nodes['cpe_match']:
				part = cpe_match['cpe23Uri'].split(':')[2]
				all_parts.add(part)
		else:
			for children in nodes['children']:
				for cpe_match in children['cpe_match']:
					part = cpe_match['cpe23Uri'].split(':')[2]
					all_parts.add(part)

	if(len(cve_items['cve']['problemtype']['problemtype_data'][0]['description']) > 0):
		CWE_Id = cve_items['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']
	else:
		continue

	first_part = CVE_Id + "\t" + description + "\t" + confi_impact + "\t" + integrity_impact + "\t" + availability_impact + "\t" + base_severity

	#sys.exit()
	write_to_csv(first_part, flat, CWE_Id, all_parts, base_score)
	#sys.exit()

file_location_2019 = os.path.join(os.getcwd(), "data", "nvdcve-1.0-2019.json")
jsonfile = open(file_location_2019)
cve_data = json.loads(jsonfile.read())

jsonfile.close()

for cve_items in cve_data['CVE_Items']:
	flat = {}
	#dict_index = 0

	url_1 = url_2 = description = attack_vector = attack_complexity = privileges_required = user_interaction = scope = confi_impact = integrity_impact = availability_impact = base_score = base_severity = exploitability_score = impact_score = ''	
	
	keys_cve_items = cve_items.keys()
	
	CVE_Id = cve_items['cve']['CVE_data_meta']['ID']
	
	try:
		url_1 = cve_items['cve']['references']['reference_data'][0]['url']
	except IndexError:
		url_1 = ''

	try:
		url_2 = cve_items['cve']['references']['reference_data'][1]['url']
	except IndexError:
		url_2 = ''
		
	description = cve_items['cve']['description']['description_data'][0]['value']

	if(len(cve_items['impact']) != 0):
		attack_vector = cve_items['impact']['baseMetricV3']['cvssV3']['attackVector']
		attack_complexity = cve_items['impact']['baseMetricV3']['cvssV3']['attackComplexity']
		privileges_required = cve_items['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
		user_interaction = cve_items['impact']['baseMetricV3']['cvssV3']['userInteraction']
		scope = cve_items['impact']['baseMetricV3']['cvssV3']['scope']
		confi_impact = cve_items['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
		integrity_impact = cve_items['impact']['baseMetricV3']['cvssV3']['integrityImpact']
		availability_impact = cve_items['impact']['baseMetricV3']['cvssV3']['availabilityImpact']
		base_score = cve_items['impact']['baseMetricV3']['cvssV3']['baseScore']
		base_severity = cve_items['impact']['baseMetricV3']['cvssV3']['baseSeverity']
		exploitability_score = cve_items['impact']['baseMetricV3']['exploitabilityScore']
		impact_score = cve_items['impact']['baseMetricV3']['impactScore']

	for vendor_data in cve_items['cve']['affects']['vendor']['vendor_data']:
		#primary_id = primary_id + 1
		flat_list = []
		vendor_name = vendor_data['vendor_name']

		for products in vendor_data['product']['product_data']:
			new_string = ''
			dict_index = dict_index + 1
			product_name = products['product_name']
			no_of_versions = len(products['version']['version_data'])
			new_string = vendor_name + '\t' + product_name + '\t' + str(no_of_versions)
			flat[dict_index] = new_string
			
	'''		
	first_part = CVE_Id + "\t" + attack_vector + "\t" + attack_complexity + "\t" + privileges_required + "\t" + user_interaction + "\t" + scope + "\t" + confi_impact + "\t" + integrity_impact + "\t" + availability_impact + "\t" + str(base_score) + "\t" + base_severity + "\t" + str(exploitability_score) + "\t" + str(impact_score)
	'''
	
	all_parts = set()
	for nodes in cve_items['configurations']['nodes']:
		if('cpe_match' in nodes):
			for cpe_match in nodes['cpe_match']:
				part = cpe_match['cpe23Uri'].split(':')[2]
				all_parts.add(part)
		else:
			for children in nodes['children']:
				for cpe_match in children['cpe_match']:
					part = cpe_match['cpe23Uri'].split(':')[2]
					all_parts.add(part)

	if(len(cve_items['cve']['problemtype']['problemtype_data'][0]['description']) > 0):
		CWE_Id = cve_items['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']
	else:
		continue

	first_part = CVE_Id + "\t" + description + "\t" + confi_impact + "\t" + integrity_impact + "\t" + availability_impact + "\t" + base_severity

	#sys.exit()
	write_to_csv(first_part, flat, CWE_Id, all_parts, base_score)
	#sys.exit()
	
