import json
import sys
import os
import pandas as pd
import numpy as np
import re
from operator import itemgetter

from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import plot_confusion_matrix

import matplotlib.pyplot as plt
import seaborn as sns

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

class NLPModel:

	def __init__(self, X_train, X_test, y_train, y_test):
		self.X_train = X_train
		self.X_test = X_test
		self.y_train = y_train
		self.y_test = y_test

	def clean_vulnerability_description(self, desc):
		version_pattern_1 = r"((\d+\.)+\d+-\d+\.\d+)" # for patterns like 10.0-10.4
		version_pattern_2 = r"((\d+\.)+\d+-[\d\w]+)" # for patterns like 7.6.3-rev37 or 7.0.7-24
		version_pattern_3 = r"((\d+\.)+[\d\w]+)" # for patterns like 5.9.1.10 or 2.2.0
		file_address_1 = r"(((\w+\.?\w+)\/)+(\w+\.)*\w+)" # for patterns like public/index.php/home/memberaddress/index.html or public/index.php/home/memberaddress/edit/address_id/2.html or libjasper/jpc/jpc_enc.c
		file_name = r"(\w+\.\w+)" # for matching file names like 2345BdPcSafe.sys
		file_address_2 = r"((\\\w+\.?\w+)+(\.?\w+)*)" # for patterns like \Lib\Lib\Action\Admin\DataAction.class.php
		punctuations = r"[\.,();:]" # for removing punctuations like comma, dot, brackets, etc.
		version_pattern_4 = r"\w{3}-\w{3}-\d{4}" # for patterns like ZDI-CAN-5762
		android_version_pattern = r"Android-(\d\.)*\d" # for patterns like Android-7.0, Android-7.1.1
		cvss_vector_string_pattern = r"CVSS:\d\.\d(\/\w{1,2}:\w{1})+" # for patterns like CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:N/A:N

		desc = re.sub(r"|".join((version_pattern_1, version_pattern_2, android_version_pattern, cvss_vector_string_pattern, version_pattern_3, file_address_1, file_name, file_address_2, version_pattern_4)), "", desc)
		desc = re.sub(punctuations, "", desc)
		desc = re.sub(r"\d+", "", desc) # removing any remaining digits
		desc = re.sub(r"\s+", " ", desc)

		return desc.lower()

	def print_text_with_target(self, desc, output):
		print(desc, output)

	def build_model(self):
		#clean_vulnerability_description_vector = np.vectorize(self.clean_vulnerability_description)(self.X_train)
		X_train_clean = np.vectorize(self.clean_vulnerability_description)(self.X_train)
		X_test_clean = np.vectorize(self.clean_vulnerability_description)(self.X_test)

		'''
		X_train_clean_tokenized = map(PreProcessing.convert_string_to_tokens, X_train_clean)
		X_test_clean_tokenized = map(PreProcessing.convert_string_to_tokens, X_test_clean)
		'''
		self.count_vect = CountVectorizer(
			preprocessor=lambda x: x,
			tokenizer = lambda x: x.split(" "),
			ngram_range = (1, 3)
		)

		x_train_count_vect = self.count_vect.fit_transform(X_train_clean)
		x_test_count_vect = self.count_vect.transform(X_test_clean)

		self.lr = LogisticRegression(max_iter = 2000)
		self.lr.fit(X = x_train_count_vect, y = self.y_train)
		predictions = self.lr.predict(X = x_test_count_vect)
		print(predictions)

		return predictions

	def get_top_bottom_features(self, label_encoder_object):

		feature_names = [feature for feature, index in sorted(self.count_vect.vocabulary_.items(), key = itemgetter(1))]

		for i, category in enumerate(self.lr.classes_):
			coef_i = self.lr.coef_[i]
			coef_features = sorted(zip(coef_i, feature_names), key = itemgetter(0), reverse = True)

			print(label_encoder_object.inverse_transform([category]))
			print(coef_features[:20])
			print(coef_features[:-20:-1])

			Visualizer.visualize_imp_features(top_feature_coef_list = coef_features[:20], bottom_feature_coef_list = coef_features[:-20:-1], title = label_encoder_object.inverse_transform([category])[0])



	string_to_remove_rows = "** reject **  do not use this candidate number." # description unavailable

	@classmethod
	def make_is_remove(cls, desc):
		if(desc.startswith(cls.string_to_remove_rows)):
			return True
		return False

	def print_metrics(self, predictions):
		cm = confusion_matrix(self.y_test, predictions, labels = [0, 1, 2, 3])
		print(cm)

		recall = np.diag(cm) / np.sum(cm, axis = 1)
		precision = np.diag(cm) / np.sum(cm, axis = 0)

		print(recall)
		print(precision)


class PreProcessing:

	@staticmethod
	def convert_target_categorical(continuous_value):

		if(continuous_value >= 0.1 and continuous_value <= 3.99):
			return "LOW"
		elif(continuous_value >= 4.0 and continuous_value <= 6.99):
			return "MEDIUM"
		elif(continuous_value >= 7.0 and continuous_value <= 8.99):
			return "HIGH"
		else:
			return "CRITICAL"

	@staticmethod
	def convert_string_to_tokens(description):
		return description.split(" ")


class Visualizer:

	def __init__(self):
		super().__init__()

	@staticmethod
	def visualize_imp_features(top_feature_coef_list, bottom_feature_coef_list, title = None):
		top_features = [i[1] for i in top_feature_coef_list]
		top_coefficients = [i[0] for i in top_feature_coef_list]

		bottom_features = [i[1] for i in bottom_feature_coef_list]
		bottom_coefficients = [i[0] for i in bottom_feature_coef_list]

		combined_coefficients = bottom_coefficients[:]
		combined_coefficients.extend(top_coefficients[::-1])
		combined_features = bottom_features[:]
		combined_features.extend(top_features[::-1])

		combined_colours = ["red" if index < len(bottom_coefficients) else "green" for index in range(0, len(combined_coefficients))]

		plt.tight_layout()
		plt.barh(y = np.arange(start = 0, stop = len(combined_coefficients)), width = combined_coefficients, color = combined_colours)
		plt.yticks(ticks = np.arange(start = 0, stop = len(combined_features)), labels = combined_features)
		plt.xlabel("word importance")
		plt.title(label = title)

		plt.show()

	@staticmethod
	def show_confusion_matrix(actual_output, predicted_output, label_encoder_object):
		cm = confusion_matrix(actual_output, predicted_output, labels = [0, 1, 3, 2])
		df_cm = pd.DataFrame(
			cm,
			index = [label_encoder_object.inverse_transform([i])[0] for i in [0, 1, 3, 2]],
			columns = [label_encoder_object.inverse_transform([i])[0] for i in [0, 1, 3, 2]]
		)

		print(df_cm)

		sns.heatmap(df_cm, annot = True, fmt = "d")
		plt.xlabel("Predicted")
		plt.ylabel("Actual")

		plt.show()

			
if(__name__ == "__main__"):
	data_obj_2019 = LoadData(json_file_name = "nvdcve-1.0-2019.json")
	data_obj_2019.load_file()
	df_2019 = data_obj_2019.get_dataframe()

	data_obj_2018 = LoadData(json_file_name = "nvdcve-1.0-2018.json")
	data_obj_2018.load_file()
	df_2018 = data_obj_2018.get_dataframe()

	df_2018["is_remove"] = df_2018["description"].apply(lambda x: NLPModel.make_is_remove(x))
	df_2019["is_remove"] = df_2019["description"].apply(lambda x: NLPModel.make_is_remove(x))

	df_2018 = df_2018.loc[~df_2018["is_remove"]]
	df_2019 = df_2019.loc[~df_2018["is_remove"]]

	df_2018["categorical_target"] = df_2018["target"].apply(lambda x: PreProcessing.convert_target_categorical(x))
	df_2019["categorical_target"] = df_2019["target"].apply(lambda x: PreProcessing.convert_target_categorical(x))

	le_obj = LabelEncoder()
	df_2018["categorical_target"] = le_obj.fit_transform(df_2018["categorical_target"].values)
	df_2019["categorical_target"] = le_obj.transform(df_2019["categorical_target"].values)

	print(df_2018)
	print(df_2019)

	nlp_model_object = NLPModel(X_train = df_2018["description"].values, X_test = df_2019["description"].values, y_train = df_2018["categorical_target"].values, y_test = df_2019["categorical_target"].values)
	predictions = nlp_model_object.build_model()
	nlp_model_object.print_metrics(predictions = predictions)
	nlp_model_object.get_top_bottom_features(le_obj)

	Visualizer.show_confusion_matrix(df_2019["categorical_target"].values, predictions, label_encoder_object = le_obj)
