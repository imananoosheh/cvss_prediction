from cvss_prediction import PreProcessing, NLPDeploymentService
import pickle

# creating a global service object to be used on demand.
# NOTE: explain better the services and what exactly the class(object) are able to do or possess.
nlp_deployment_obj = NLPDeploymentService()


def testing_single_description(input_string):
    """
    :param input_string: the single description that describe the vulnerability, contained in the json file from nist.gov, under description_data.
    :return: string of cleaned description along with vectors and qualitative prediction
    """
    # NOTICE: return is TO Be Decide.

    new_vulnerability_desc = str(input_string)

    predicted_category = nlp_deployment_obj.test_on_single_desc(
        vulnerability_description=new_vulnerability_desc,
        trained_model_location='./data/trained_models/tf_idf_vect_model_2017_2018_2019_Model.pkl',
        vectorizer_obj_file='./data/trained_models/tf_idf_vect_model_2017_2018_2019_Vectorizer.pkl'
    )

    return predicted_category
