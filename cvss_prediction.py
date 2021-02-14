import json
import sys
import os
import pandas as pd
import numpy as np
import re
from operator import itemgetter
import collections
import itertools
import pickle

from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, recall_score, precision_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import plot_confusion_matrix
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
import tensorflow as tf

import matplotlib.pyplot as plt
import seaborn as sns
import nltk
from nltk.corpus import stopwords

nltk.download('stopwords')
stop_words = list(stopwords.words('english'))


class LoadData:

    def __init__(self, json_file_name, version_number="1.0"):
        """
        Converting NVD-CVE data feed from nested json (https://nvd.nist.gov/vuln/data-feeds) to another structured format. The main goal is to analyze historical CVSS data efficiently using ML/NLP based approach.

        Arguments:
            json_file_name: A string representating file path of NVD-CVE file. Required extention is .json
            version_number: A string representating version of NVD CVE json format. Acceptable values: 1.0 and 1.1

        Returns:
            None.
        """

        self.json_file = os.path.join(os.getcwd(), "data", json_file_name)
        self.version_number = version_number

    def load_file(self):
        """
        Loading json file to memory in dictionary data structure.

        Arguments:
            None. This function sets value in cve_data attribute.

        Returns:
            None.
        """

        if (self.version_number == "1.0"):
            jsonfile = open(self.json_file)
            self.cve_data = json.loads(jsonfile.read())
        else:
            jsonfile = open(self.json_file, encoding='utf-8')
            self.cve_data = json.loads(jsonfile.read())

        jsonfile.close()

    def get_dataframe(self):
        """
        Convert the loaded dictionary (from cve_data) to Pandas DataFrame.

        Arguments:
            None.

        Returns:
            df: DataFrame having one cve-id per row with different columns representating base metric version 3.0. The target columns is "Base Score".
        """

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

            if (len(cve_items['cve']['problemtype']['problemtype_data'][0]['description']) > 0):
                CWE_Id = cve_items['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']

            if (len(cve_items['impact']) != 0):

                if ('baseMetricV3' not in cve_items['impact']):
                    continue

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

    def __init__(self, X_train, y_train, X_test=None, y_test=None):
        self.X_train = X_train
        self.X_test = X_test
        self.y_train = y_train
        self.y_test = y_test

    def print_text_with_target(self, desc, output):
        print(desc, output)

    def custom_preprocessor(self, x):
        return x

    def custom_tokenizer(self, x):
        return x.split(" ")

    def build_model_count(self):
        """
        Train Logistic Regression model based on Count Vectorizer based approach. Apply inference on test set if testing data is passed while building object.

        Arguments:
            None. It trains the model based on training data stored in this object

        Returns:
            predictions: Model inference on a specific set of data (train set or test set) depending on object initialization.
        """
        # to-do: experiment with other machine learning algorithms (like Random Forest, LightGBM, XGBoost, etc.)

        X_train_clean = np.vectorize(PreProcessing.clean_vulnerability_description)(self.X_train)

        count_vect = CountVectorizer(
            preprocessor=self.custom_preprocessor,
            tokenizer=self.custom_tokenizer,
            ngram_range=(1, 3)
        )

        x_train_count_vect = count_vect.fit_transform(X_train_clean)

        lr = LogisticRegression(max_iter=2000)
        lr.fit(X=x_train_count_vect, y=self.y_train)

        if (self.X_test is not None):
            X_test_clean = np.vectorize(PreProcessing.clean_vulnerability_description)(self.X_test)
            x_test_count_vect = count_vect.transform(X_test_clean)
            predictions = lr.predict(X=x_test_count_vect)

        else:
            predictions = lr.predict(X=x_train_count_vect)

        self.model = lr
        self.vectorizer = count_vect

        '''
        clf = LinearSVC()
        clf.fit(x_train_count_vect, self.y_train)
        predictions = clf.predict(x_test_count_vect)
        '''
        return predictions

    def build_model_tfidf(self):
        """
        Train Logistic Regression model based on TF-IDF (Term Frequency - Inverse Document Frequency) Vectorizer based approach. Apply inference on test set if testing data is passed while building object.

        Arguments:
            None. It trains the model based on training data stored in this object

        Returns:
            predictions: Model inference on a specific set of data (train set or test set) depending on object initialization.
        """
        # to-do: experiment with other machine learning algorithms (like Random Forest, LightGBM, XGBoost, etc.)

        X_train_clean = np.vectorize(PreProcessing.clean_vulnerability_description)(self.X_train)

        tf_idf_vect = TfidfVectorizer(
            preprocessor=self.custom_preprocessor,
            tokenizer=self.custom_tokenizer,
            ngram_range=(1, 3)
        )

        x_train_tf_idf_vect = tf_idf_vect.fit_transform(X_train_clean)

        lr = LogisticRegression(max_iter=2000)
        lr.fit(X=x_train_tf_idf_vect, y=self.y_train)

        if (self.X_test is not None):
            X_test_clean = np.vectorize(PreProcessing.clean_vulnerability_description)(self.X_test)
            x_test_tf_idf_vect = tf_idf_vect.transform(X_test_clean)
            predictions = lr.predict(X=x_test_tf_idf_vect)

        else:
            predictions = lr.predict(X=x_train_tf_idf_vect)

        self.model = lr
        self.vectorizer = tf_idf_vect

        return predictions

    def load_word_embedding(self, file_path):

        f = open(file_path, "r", encoding='utf-8')
        wordVectors = {}

        for each_line in f:
            splittedLine = each_line.split()
            word = splittedLine[0]
            vector = splittedLine[1:]

            wordVectors[word] = np.asarray(vector).astype(np.float)

        return wordVectors

    def mean_embedding(self, words):

        sentence_embedding = []

        for w in words:
            if w in self.word_vectors_dict:
                sentence_embedding.append(self.word_vectors_dict[w])

        if (len(sentence_embedding) > 0):
            return np.mean(sentence_embedding, axis=0)
        else:
            return np.zeros(len(self.word_vectors_dict[list(self.word_vectors_dict.keys())[0]]))

    def build_model_average_word_embedding(self):

        tokens_train = [PreProcessing.clean_vulnerability_description(description).split() for description in
                        self.X_train]
        tokens_test = [PreProcessing.clean_vulnerability_description(description).split() for description in
                       self.X_test]

        # print(tokens_train[0])
        self.word_vectors_dict = self.load_word_embedding(file_path="./glove.6B/glove.6B.100d.txt")

        embedding_train = [self.mean_embedding(tokens) for tokens in tokens_train]
        embedding_test = [self.mean_embedding(tokens) for tokens in tokens_test]

        y_train_one_hot = PreProcessing.get_one_hot_vectors(self.y_train)

        print(np.asarray(embedding_train))
        print(np.asarray(embedding_train).shape)
        '''
        clf = LogisticRegression(max_iter = 2000)
        clf.fit(np.asarray(embedding_train), self.y_train)
        predictions = clf.predict(np.asarray(embedding_test))
        '''

        clf = DeepLearningModels().MLP()
        clf.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

        clf.fit(np.asarray(embedding_train), y_train_one_hot, batch_size=10, epochs=50)
        prediction_prob = clf.predict(np.asarray(embedding_test))
        predictions = np.argmax(prediction_prob, axis=1)

        return predictions

    def get_top_bottom_features(self, label_encoder_object):

        feature_names = [feature for feature, index in sorted(self.count_vect.vocabulary_.items(), key=itemgetter(1))]

        for i, category in enumerate(self.lr.classes_):
            coef_i = self.lr.coef_[i]
            coef_features = sorted(zip(coef_i, feature_names), key=itemgetter(0), reverse=True)

            print(label_encoder_object.inverse_transform([category]))
            print(coef_features[:20])
            print(coef_features[:-20:-1])

            Visualizer.visualize_imp_features(top_feature_coef_list=coef_features[:20],
                                              bottom_feature_coef_list=coef_features[:-20:-1],
                                              title=label_encoder_object.inverse_transform([category])[0])

    def print_metrics(self, predictions):
        cm = confusion_matrix(self.y_test, predictions, labels=[0, 1, 2, 3])
        print(cm)

        recall = np.diag(cm) / np.sum(cm, axis=1)
        precision = np.diag(cm) / np.sum(cm, axis=0)

        print(recall)
        print(precision)

    def print_accuracy(self, predictions):

        print(f1_score(self.y_test, predictions, average="macro"))
        print(precision_score(self.y_test, predictions, average="macro"))
        print(recall_score(self.y_test, predictions, average="macro"))

    def save_nlp_model(self, file_name: str):
        """
        Saving Machine Learning model weights in an approariate formate, so it could be later used in inference

        Arguments:
            file_name: name of file to store the model weights

        Returns:
            None. It just saves the model weights and sentence to vectorizer object in the given file
        """

        if (hasattr(self, 'vectorizer')):
            with open(file_name + '_Vectorizer.pkl', 'wb') as f:
                pickle.dump(self.vectorizer, f)

        if (self.is_pickleable()):
            with open(file_name + '_Model.pkl', 'wb') as f:
                pickle.dump(self.model, f)
        else:

            self.model.save(file_name + "_Model.h5")

    def load_nlp_model(self, file_name):
        """
        Load a saved NLP model in memory.

        Arguments:
            file_name: file path where NLP model is stored. Extentions: .pkl (for sklearn based models), .h5 (for tensorflow based models)
        """

        if (file_name.split('.')[-1] == "pkl"):
            model = pickle.load(open(file_name, 'rb'))
        else:

            model = tf.keras.models.load_model(file_name)

        return model

    def is_pickleable(self):
        """
        Function to check if Machine Learning model is pickleable or not.

        Arguments:
            None

        Returns:
            True if model is pickleble, False otherwise.
        """

        try:
            pickle.dumps(self.model)
        except TypeError:
            return False

        return True

    def test_on_single_desc(self, vulnerability_description, trained_model, vectorizer_obj=None):

        """
        Apply the trained model to predict the CVSS Category of a new description.

        Arguments:
            vulnerability_description: the vulnerability description to run inference on
            trained_model: NLP model (tensorflow or scikit learn based) trained on given dataset
            vectorizer_obj: tokenizer fitted on specific n-gram

        Returns:
            predicted_category: predicted severity of given vulnerability
        """

        model = self.load_nlp_model(trained_model)
        clean_desc = PreProcessing.clean_vulnerability_description(vulnerability_description)

        if (vectorizer_obj):
            clean_desc_vec = np.asarray(vectorizer_obj.transform(clean_desc))

        predicted_category = model.predict(clean_desc_vec)

        return predicted_category


class CountCNNVectorizer:

    def fit_transform(self, sentenses):

        tokens = [sentense.split() for sentense in sentenses]

        tokens_1d = list(itertools.chain.from_iterable(tokens))

        self._max_len = max([len(s) for s in tokens])
        self._w2i = self.get_word_to_index(tokens_1d)
        self._vocan_len = len(self._w2i) + 1

        return self.transform(sentenses)

    def transform(self, sentenses):

        if (not hasattr(self, '_w2i')):
            raise ValueError("Vectorizer is not fitted on any sentense")

        sentence_tokens = [sentense.split() for sentense in sentenses]
        encoding = []

        for sentence in sentence_tokens:

            sentence_encoding = []

            for token in sentence:
                sentence_encoding.append(self._w2i[token])

            encoding.append(sentence_encoding)

        return encoding

    def get_word_to_index(self, tokens):

        w2i = collections.defaultdict(int)
        token_frequency = collections.Counter(tokens)

        token_counter = 1

        for t in token_frequency.items():
            w2i[t[0]] = token_counter
            token_counter = token_counter + 1

        return w2i


class NLPModelCNN(NLPModel):

    def __init__(self, X_train, y_train, X_test=None, y_test=None):
        super().__init__(X_train, y_train, X_test, y_test)
        self.embedding_dim = 100

    def build_cnn_model(self):
        '''
        tokens_train = [PreProcessing.clean_vulnerability_description(description).split() for description in self.X_train]
        tokens_test = [PreProcessing.clean_vulnerability_description(description).split() for description in self.X_test]

        train_tokens_1d = list(itertools.chain.from_iterable(tokens_train))
        max_len = max([len(s) for s in tokens_train])

        self.word_vectors_dict = self.load_word_embedding(file_path = "./glove.6B/glove.6B.100d.txt")
        self.w2i = self.get_word_to_index(train_tokens_1d)

        self.vocab_len = len(self.w2i) + 1

        train_encoding = self.get_tokens_encoding(tokens_train)
        test_encoding = self.get_tokens_encoding(tokens_test)
        '''

        X_train_cleaned = [PreProcessing.clean_vulnerability_description(desc) for desc in self.X_train]

        self.word_vectors_dict = self.load_word_embedding(file_path="./glove.6B/glove.6B.100d.txt")

        vectorizer = CountCNNVectorizer()
        train_encoding = vectorizer.fit_transform(sentenses=X_train_cleaned)

        train_encoding_padded = tf.keras.preprocessing.sequence.pad_sequences(train_encoding,
                                                                              maxlen=vectorizer._max_len,
                                                                              padding="post")

        embedding_matrix = self.get_embedding_matrix(word_to_index_dict=vectorizer._w2i,
                                                     vocab_len=vectorizer._vocan_len)
        y_train_one_hot = PreProcessing.get_one_hot_vectors(self.y_train)

        clf = DeepLearningModels().MultiChannelCNN(vectorizer._max_len, vectorizer._vocan_len, self.embedding_dim,
                                                   embedding_matrix)
        clf.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

        clf.fit(train_encoding_padded, y_train_one_hot, batch_size=1, epochs=2)

        if (self.X_test is not None):
            X_test_cleaned = [PreProcessing.clean_vulnerability_description(desc) for desc in self.X_test]
            test_encoding = vectorizer.transform(sentenses=X_test_cleaned)
            test_encoding_paded = tf.keras.preprocessing.sequence.pad_sequences(test_encoding,
                                                                                maxlen=vectorizer._max_len,
                                                                                padding="post")

            prediction_prob = clf.predict(test_encoding_paded)

        else:
            prediction_prob = clf.predict(train_encoding_padded)

        predictions = np.argmax(prediction_prob, axis=1)

        self.model = clf
        self.vectorizer = vectorizer

        return predictions

    '''
    def get_tokens_encoding(self, sentence_tokens):

        encoding = []

        for sentence in sentence_tokens:

            sentence_encoding = []

            for token in sentence:
                sentence_encoding.append(self.w2i[token])

            encoding.append(sentence_encoding)

        return encoding


    def get_word_to_index(self, tokens):

        w2i = collections.defaultdict(int)
        token_frequency = collections.Counter(tokens)

        token_counter = 1

        for t in token_frequency.items():
            w2i[t[0]] = token_counter
            token_counter = token_counter + 1

        return w2i
    '''

    def get_embedding_matrix(self, word_to_index_dict, vocab_len):

        embedding_matrix = np.zeros((vocab_len, self.embedding_dim))

        for w in word_to_index_dict:
            try:
                embedding_matrix[word_to_index_dict[w], :] = np.array(self.word_vectors_dict[w])
            except KeyError:
                embedding_matrix[word_to_index_dict[w], :] = np.zeros(self.embedding_dim)

        return embedding_matrix


class NLPDeploymentService:

    def load_label_encoder(self, file_name):

        with open(file_name, 'rb') as f:
            le_obj = pickle.load(f)

        return le_obj

    def load_nlp_model(self, file_name):

        if (file_name.split('.')[-1] == "pkl"):
            model = pickle.load(open(file_name, 'rb'))
        else:
            model = tf.keras.models.load_model(file_name)

        return model

    def load_nlp_vectorizer(self, file_name):

        with open(file_name, 'rb') as f:
            vectorizer_obj = pickle.load(f)

        return vectorizer_obj

    def test_on_single_desc(self, vulnerability_description, trained_model_location, vectorizer_obj_file=None):

        """
        Apply the trained model to predict the CVSS Category of a new description.

        Arguments:
            vulnerability_description: the vulnerability description to run inference on
            trained_model: NLP model (tensorflow or scikit learn based) trained on given dataset
            vectorizer_obj_file: tokenizer fitted on specific n-gram

        Returns:
            predicted_category: predicted severity of given vulnerability
        """

        label_encoder = self.load_label_encoder('./data/trained_models/categories.pkl')
        model = self.load_nlp_model(trained_model_location)
        clean_desc = PreProcessing.clean_vulnerability_description(vulnerability_description)

        print(clean_desc)

        if (vectorizer_obj_file):
            vectorizer_obj = self.load_nlp_vectorizer(vectorizer_obj_file)
            clean_desc_vec = vectorizer_obj.transform([clean_desc])

        if (trained_model_location.split('.')[-1] == "pkl"):
            predicted_category = model.predict(clean_desc_vec)
            print(model.predict_proba(clean_desc_vec))
        else:
            test_encoding_paded = tf.keras.preprocessing.sequence.pad_sequences(clean_desc_vec,
                                                                                maxlen=vectorizer_obj._max_len,
                                                                                padding="post")
            prediction_prob = model.predict(test_encoding_paded)
            predicted_category = np.argmax(prediction_prob, axis=1)
            print(prediction_prob)

        print(label_encoder.classes_)
        return label_encoder.inverse_transform(predicted_category.reshape(-1, 1))


class PreProcessing:

    @staticmethod
    def convert_target_categorical(continuous_value):

        if (continuous_value >= 0.1 and continuous_value <= 3.99):
            return "LOW"
        elif (continuous_value >= 4.0 and continuous_value <= 6.99):
            return "MEDIUM"
        elif (continuous_value >= 7.0 and continuous_value <= 8.99):
            return "HIGH"
        else:
            return "CRITICAL"

    @staticmethod
    def convert_string_to_tokens(description):
        return description.split(" ")

    string_to_remove_rows = "** reject **  do not use this candidate number."  # description unavailable

    @classmethod
    def make_is_remove(cls, desc):
        if (desc.startswith(cls.string_to_remove_rows)):
            return True
        return False

    @staticmethod
    def get_one_hot_vectors(categories):

        one_hot = np.zeros((len(categories), 4))

        for i in range(0, len(categories)):
            # print(i, categories[i])
            one_hot[i, :] = PreProcessing.get_vector_by_label(categories[i])

        return one_hot

    @staticmethod
    def get_vector_by_label(label):

        if (label == 0):
            return np.array([1, 0, 0, 0])
        elif (label == 1):
            return np.array([0, 1, 0, 0])
        elif (label == 2):
            return np.array([0, 0, 1, 0])
        elif (label == 3):
            return np.array([0, 0, 0, 1])

    @staticmethod
    def clean_vulnerability_description(desc):

        version_pattern_1 = r"((\d+\.)+\d+-\d+\.\d+)"  # for patterns like 10.0-10.4
        version_pattern_2 = r"((\d+\.)+\d+-[\d\w]+)"  # for patterns like 7.6.3-rev37 or 7.0.7-24
        version_pattern_3 = r"((\d+\.)+[\d\w]+)"  # for patterns like 5.9.1.10 or 2.2.0
        file_address_1 = r"(((\w+\.?\w+)\/)+(\w+\.)*\w+)"  # for patterns like public/index.php/home/memberaddress/index.html or public/index.php/home/memberaddress/edit/address_id/2.html or libjasper/jpc/jpc_enc.c
        file_name = r"(\w+\.\w+)"  # for matching file names like 2345BdPcSafe.sys
        file_address_2 = r"((\\\w+\.?\w+)+(\.?\w+)*)"  # for patterns like \Lib\Lib\Action\Admin\DataAction.class.php
        punctuations = r"[\.,();:?]"  # for removing punctuations like comma, dot, brackets, etc.
        version_pattern_4 = r"\w{3}-\w{3}-\d{4}"  # for patterns like ZDI-CAN-5762
        android_version_pattern = r"Android-(\d\.)*\d"  # for patterns like Android-7.0, Android-7.1.1
        cvss_vector_string_pattern = r"CVSS:\d\.\d(\/\w{1,2}:\w{1})+"  # for patterns like CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:N/A:N

        desc = re.sub(r"|".join((version_pattern_1, version_pattern_2, android_version_pattern,
                                 cvss_vector_string_pattern, version_pattern_3, file_address_1, file_name,
                                 file_address_2, version_pattern_4)), "", desc)
        desc = re.sub(punctuations, "", desc)
        desc = re.sub(r"\d+", "", desc)  # removing any remaining digits
        desc = re.sub(r"\s+", " ", desc)

        desc_clean = []

        for word in desc.lower().split(" "):
            if (word not in stop_words):
                desc_clean.append(word)

        # return desc.lower()
        return " ".join(w for w in desc_clean)


class DeepLearningModels:

    def MLP(self):
        model = tf.keras.models.Sequential()
        # model.add(tf.keras.Input())
        model.add(tf.keras.layers.Dense(100, activation='tanh'))
        model.add(tf.keras.layers.Dense(50))
        model.add(tf.keras.layers.Dense(4, activation='softmax'))

        return model

    def CNN(self, max_len, vocan_len, embedding_dim, embedding_matrix):
        input_layer = tf.keras.layers.Input(shape=(max_len,))
        embedding_layer = tf.keras.layers.Embedding(vocan_len, embedding_dim, weights=[embedding_matrix],
                                                    input_length=max_len, trainable=False)(input_layer)
        conv_layer = tf.keras.layers.Conv1D(filters=32, kernel_size=2, activation="relu")(embedding_layer)
        drop_layer = tf.keras.layers.Dropout(0.2)(conv_layer)
        max_pool_layer = tf.keras.layers.GlobalMaxPool1D()(drop_layer)
        output_layer = tf.keras.layers.Dense(4, activation='softmax')(max_pool_layer)

        model = tf.keras.models.Model(inputs=input_layer, outputs=output_layer)

        return model

    def MultiChannelCNN(self, max_len, vocan_len, embedding_dim, embedding_matrix):
        input_layer = tf.keras.layers.Input(shape=(max_len,))

        embedding_layer_1 = tf.keras.layers.Embedding(vocan_len, embedding_dim, weights=[embedding_matrix],
                                                      trainable=True)(input_layer)
        conv_layer_1 = tf.keras.layers.Conv1D(filters=32, kernel_size=2, activation="relu")(embedding_layer_1)
        drop_layer_1 = tf.keras.layers.Dropout(0.2)(conv_layer_1)
        max_pool_layer_1 = tf.keras.layers.GlobalMaxPool1D()(drop_layer_1)
        # output_layer_1 = tf.keras.layers.Dense(4, activation = 'softmax')(max_pool_layer_1)

        embedding_layer_2 = tf.keras.layers.Embedding(vocan_len, embedding_dim, weights=[embedding_matrix],
                                                      trainable=True)(input_layer)
        conv_layer_2 = tf.keras.layers.Conv1D(filters=32, kernel_size=1, activation="relu")(embedding_layer_2)
        drop_layer_2 = tf.keras.layers.Dropout(0.2)(conv_layer_2)
        max_pool_layer_2 = tf.keras.layers.GlobalMaxPool1D()(drop_layer_2)
        # output_layer_2 = tf.keras.layers.Dense(4, activation = 'softmax')(max_pool_layer_2)

        merged_layer = tf.keras.layers.Concatenate()([max_pool_layer_1, max_pool_layer_2])
        output_layer = tf.keras.layers.Dense(4, activation='softmax')(merged_layer)

        model = tf.keras.models.Model(inputs=input_layer, outputs=output_layer)

        return model


class Visualizer:

    def __init__(self):
        super().__init__()

    @staticmethod
    def visualize_imp_features(top_feature_coef_list, bottom_feature_coef_list, title=None):
        top_features = [i[1] for i in top_feature_coef_list]
        top_coefficients = [i[0] for i in top_feature_coef_list]

        bottom_features = [i[1] for i in bottom_feature_coef_list]
        bottom_coefficients = [i[0] for i in bottom_feature_coef_list]

        combined_coefficients = bottom_coefficients[:]
        combined_coefficients.extend(top_coefficients[::-1])
        combined_features = bottom_features[:]
        combined_features.extend(top_features[::-1])

        combined_colours = ["red" if index < len(bottom_coefficients) else "green" for index in
                            range(0, len(combined_coefficients))]

        plt.tight_layout()
        plt.barh(y=np.arange(start=0, stop=len(combined_coefficients)), width=combined_coefficients,
                 color=combined_colours)
        plt.yticks(ticks=np.arange(start=0, stop=len(combined_features)), labels=combined_features)
        plt.xlabel("word importance")
        plt.title(label=title)

        plt.show()

    @staticmethod
    def show_confusion_matrix(actual_output, predicted_output, label_encoder_object):
        cm = confusion_matrix(actual_output, predicted_output, labels=[0, 1, 3, 2])
        df_cm = pd.DataFrame(
            cm,
            index=[label_encoder_object.inverse_transform([i])[0] for i in [0, 1, 3, 2]],
            columns=[label_encoder_object.inverse_transform([i])[0] for i in [0, 1, 3, 2]]
        )

        print(df_cm)

        sns.heatmap(df_cm, annot=True, fmt="d")
        plt.xlabel("Predicted")
        plt.ylabel("Actual")

        plt.show()


if (__name__ == "__main__"):
    # bloxk of code to train and save the model

    data_obj_2019 = LoadData(json_file_name="nvdcve-1.0-2019.json")
    data_obj_2019.load_file()
    df_2019 = data_obj_2019.get_dataframe()

    data_obj_2018 = LoadData(json_file_name="nvdcve-1.0-2018.json")
    data_obj_2018.load_file()
    df_2018 = data_obj_2018.get_dataframe()

    data_obj_2017 = LoadData(json_file_name="nvdcve-1.1-2017.json", version_number="1.1")
    data_obj_2017.load_file()
    df_2017 = data_obj_2017.get_dataframe()

    df_2017["is_remove"] = df_2017["description"].apply(lambda x: PreProcessing.make_is_remove(x))
    df_2018["is_remove"] = df_2018["description"].apply(lambda x: PreProcessing.make_is_remove(x))
    df_2019["is_remove"] = df_2019["description"].apply(lambda x: PreProcessing.make_is_remove(x))

    df_2017 = df_2017.loc[~df_2017["is_remove"]]
    df_2018 = df_2018.loc[~df_2018["is_remove"]]
    df_2019 = df_2019.loc[~df_2018["is_remove"]]

    df_2017["categorical_target"] = df_2017["target"].apply(lambda x: PreProcessing.convert_target_categorical(x))
    df_2018["categorical_target"] = df_2018["target"].apply(lambda x: PreProcessing.convert_target_categorical(x))
    df_2019["categorical_target"] = df_2019["target"].apply(lambda x: PreProcessing.convert_target_categorical(x))

    le_obj = LabelEncoder()
    df_2018["categorical_target"] = le_obj.fit_transform(df_2018["categorical_target"].values)
    df_2019["categorical_target"] = le_obj.transform(df_2019["categorical_target"].values)
    df_2017["categorical_target"] = le_obj.transform(df_2017["categorical_target"].values)

    with open('./data/trained_models/categories.pkl', 'wb') as f:
        pickle.dump(le_obj, f)
    '''
    df_2017_2018_2019 = pd.concat([df_2017, df_2018, df_2019], axis = 0)


    nlp_model_object = NLPModelCNN(X_train = df_2017_2018_2019["description"].values, y_train = df_2017_2018_2019["categorical_target"].values)
    nlp_model_object.build_cnn_model()
    nlp_model_object.save_nlp_model(file_name = './data/trained_models/count_vect_cnn_model_2017_2018_2019')
    '''
    # block of code for building and saving scikit-learn based models
    '''
    nlp_model_object = NLPModel(X_train = df_2017_2018_2019["description"].values, y_train = df_2017_2018_2019["categorical_target"].values)
    nlp_model_object.build_model_tfidf()
    nlp_model_object.save_nlp_model(file_name = './data/trained_models/tf_idf_vect_model_2017_2018_2019')
    '''

    # block of code to infer model on a single description

    '''
    new_vulnerability_desc = "Under certain conditions, SAP Landscape Management enterprise edition, before version 3.0, allows custom secure parameters? default values to be part of the application logs leading to Information Disclosure."

    nlp_deployment_obj = NLPDeploymentService()
    predicted_category = nlp_deployment_obj.test_on_single_desc(
        vulnerability_description = new_vulnerability_desc, 
        trained_model_location = './data/trained_models/count_vect_cnn_model_2017_2018_2019_Model.h5',
        vectorizer_obj_file = './data/trained_models/count_vect_cnn_model_2017_2018_2019_Vectorizer.pkl'
    )

    print(predicted_category)
    '''

    # block of code to run the model on a specific set of test data, and to get confusion matrics

    # nlp_model_object.predict("Under certain conditions, SAP Landscape Management enterprise edition, before version 3.0, allows custom secure parameters? default values to be part of the application logs leading to Information Disclosure.")

    df_2017_2018 = pd.concat([df_2017, df_2018], axis=0)

    nlp_model_object = NLPModel(X_train=df_2017_2018["description"].values, X_test=df_2019["description"].values,
                                y_train=df_2017_2018["categorical_target"].values,
                                y_test=df_2019["categorical_target"].values)
    # cnn_nlp_model_object = NLPModelCNN(X_train = df_2017_2018["description"].values, X_test = df_2019["description"].values, y_train = df_2017_2018["categorical_target"].values, y_test = df_2019["categorical_target"].values)

    predictions_count = nlp_model_object.build_model_tfidf()
    # predictions_mean_embeddings = nlp_model_object.build_model_average_word_embedding()
    # predictions_cnn = cnn_nlp_model_object.build_cnn_model()

    # nlp_model_object.get_top_bottom_features(le_obj)

    # nlp_model_object.print_accuracy(predictions = predictions)
    nlp_model_object.print_metrics(predictions=predictions_count)
# nlp_model_object.print_metrics(predictions = predictions_mean_embeddings)
# cnn_nlp_model_object.print_metrics(predictions = predictions_cnn)


# Visualizer.show_confusion_matrix(df_2019["categorical_target"].values, predictions, label_encoder_object = le_obj)
