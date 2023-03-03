from flask import Flask, request
import pandas as pd
from sklearn.metrics.pairwise import pairwise_distances
import pickle


app = Flask(__name__)

@app.route('/cve_identifier', methods=['POST'])
def run_code():
    if request.headers['Content-Type'] == 'application/json':
        code = request.json.get('code')
    else:
        code = request.form.get('code')
    
    # print(code)
    output = None
    
    try:
        cve_id = pickle.load(open("cve_id.pkl", "rb"))
        descriptions_vectors = pickle.load(open("descriptions_vectors.pkl", "rb"))
        vectorizer = pickle.load(open("vectorizer.pkl", "rb"))
        test_description = code
        test_description_vector = vectorizer.transform([test_description])
        distances = pairwise_distances(test_description_vector, descriptions_vectors, metric='cosine')
        distances = distances.flatten().tolist()
        df = pd.DataFrame({'cveID': cve_id, 'distance': distances})
        df = df.sort_values(by=['distance'], ascending=True)
        # print(df.head(10))
        # output = df.head(10).to_json(orient='records')
        # output the first column of df
        output = df.head(1).to_json(orient='records')
    except Exception as e:
        output = str(e)
        
    return output


if __name__ == '__main__':
    app.run()