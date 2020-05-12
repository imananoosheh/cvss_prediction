import json
import sys
import os
import pandas as pd

class LoadData:

	def __init__(self, json_file_name):
		self.json_file = os.path.join(os.getcwd(), "data", json_file_name)

	def load_file(self):
		jsonfile = open(self.json_file)
		self.cve_data = json.loads(jsonfile.read())

		jsonfile.close()
	
	def get_dataframe(self):
		cve_id_list = []

		cwe_id_list = []
		description_list = []
		attack_vector_list = []
		attack_complexity_list = []
		privileges_required_list = []
		user_interaction_list = []
		scope_list = []
		confi_impact_list = []
		integrity_impact_list = []
		availability_impact_list = []
		base_score_list = []
		base_severity_list = []
		exploitability_score_list = []
		impact_score_list = []

		for cve_items in self.cve_data["CVE_Items"]:
			CVE_Id = cve_items['cve']['CVE_data_meta']['ID']
			description = cve_items['cve']['description']['description_data'][0]['value']

			if(len(cve_items['cve']['problemtype']['problemtype_data'][0]['description']) > 0):
				CWE_Id = cve_items['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']

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

			cve_id_list.append(CVE_Id)
			cwe_id_list.append(CWE_Id)
			description_list.append(description)
			attack_vector_list.append(attack_vector)
			attack_complexity_list.append(attack_complexity)
			privileges_required_list.append(privileges_required)
			user_interaction_list.append(user_interaction)
			scope_list.append(scope)
			confi_impact_list.append(confi_impact)
			integrity_impact_list.append(integrity_impact)
			availability_impact_list.append(availability_impact)
			base_score_list.append(base_score)
			base_severity_list.append(base_severity)
			exploitability_score_list.append(exploitability_score)
			impact_score_list.append(impact_score)

		df = pd.DataFrame({
			"CVE_Id": cve_id_list,
			"CWE_Id": cwe_id_list,
			"description": description_list,
			"attack vector": attack_vector_list,
			"attack complexity": attack_complexity_list,
			"privileges_required": privileges_required_list,
			"user interaction": user_interaction_list,
			"scope": scope_list,
			"confidentiality impact": confi_impact_list,
			"integrity impact": integrity_impact_list,
			"availability impact": availability_impact_list,
			"target": base_score_list
		})

		return df

			
if(__name__ == "__main__"):
	data_obj_2019 = LoadData(json_file_name = "nvdcve-1.0-2019.json")
	data_obj_2019.load_file()
	df_2019 = data_obj_2019.get_dataframe()

	print(df_2019)