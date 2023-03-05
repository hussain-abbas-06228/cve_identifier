from flask import Flask, request
import pandas as pd
from sklearn.metrics.pairwise import pairwise_distances
import pickle
import json
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

@app.route('/cve_identifier', methods=['POST'])
def run_code():
    if request.headers['Content-Type'] == 'application/json':
        number_of_response_cve = request.json.get('number_of_response_cve')
        desc = request.json.get('desc')
        show_distance = request.json.get('show_distance')
        show_mitre_link = request.json.get('show_mitre_link')
        show_nvd_link = request.json.get('show_nvd_link')
        show_cwe_details = request.json.get('show_cwe_details')
    else:
        number_of_response_cve = request.json.get('number_of_response_cve')
        desc = request.form.get('desc')
        show_distance = request.form.get('show_distance')
        show_mitre_link = request.form.get('show_mitre_link')
        show_nvd_link = request.form.get('show_nvd_link')
        show_cwe_details = request.form.get('show_cwe_details')
    
    # print(code)
    output = None
    
    try:
        cve_id = pickle.load(open("cve_id.pkl", "rb"))
        descriptions_vectors = pickle.load(open("descriptions_vectors.pkl", "rb"))
        vectorizer = pickle.load(open("vectorizer.pkl", "rb"))
        test_description = desc
        test_description_vector = vectorizer.transform([test_description])
        distances = pairwise_distances(test_description_vector, descriptions_vectors, metric='cosine')
        distances = distances.flatten().tolist()
        df = pd.DataFrame({'cveID': cve_id, 'distance': distances})
        df = df.sort_values(by=['distance'], ascending=True)
        # add column to df with the name DataBase_CVE_Count and in the values store len(cve_id)
        df['DataBase_CVE_Count'] = len(cve_id)
        # add column to df with the name mitre_link and add a string concatinating the cve_id with "www"
        df['mitre_link'] = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + df['cveID'].astype(str).str.lower()
        df['nvd_link'] = "https://nvd.nist.gov/vuln/detail/" + df['cveID'].astype(str).str.upper()
        
        print(df.head(number_of_response_cve))
        
        # add new column to df with the name cwe_id and cwe_name
        

        # loop through the df and get the cwe_id and cwe_name
        count = 0
        for index, row in df.iterrows():
            if count == number_of_response_cve:
                break
            # print(row['mitre_link'])
            URL = row['nvd_link']
            headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36"}
            print("reached here")
            page = requests.get(URL,headers=headers)
            print("reached here2")
            soup = BeautifulSoup(page.content, 'html.parser')
            results = soup.find(id='vulnTechnicalDetailsDiv')
            
            cwe = results.text
            # remove spaces from cwe
            # cwe = cwe.replace(" ", "")
            # split where newline
            cwe = cwe.splitlines()
            # remove empty strings
            
            cwe = list(filter(None, cwe))
            print(cwe)
            cweName = cwe[-2]
            cweId = cwe[-3]
            # print(cweId)
            # print(cweName)
            # make the new link
            cweLink = "https://cwe.mitre.org/data/definitions/" + cweId[4:] + ".html"
            
            # add new columns to df for cweName,cweId and cweLink
            df.loc[index, 'cweName'] = cweName
            df.loc[index, 'cweId'] = cweId
            df.loc[index, 'cweLink'] = cweLink


            count += 1


        if show_distance == False:
            # delete distance column
            df = df.drop(['distance'], axis=1)
        else:
            pass

        if show_mitre_link == False:
            # delete mitre_link column
            df = df.drop(['mitre_link'], axis=1)
        else:
            pass

        if show_nvd_link == False:
            # delete nvd_link column
            df = df.drop(['nvd_link'], axis=1)
        else:
            pass

        if show_cwe_details == False:
            # delete cweName,cweId and cweLink columns
            df = df.drop(['cweName','cweId','cweLink'], axis=1)
        else:
            pass


        output = df.head(number_of_response_cve)


        output = json.dumps(output.to_dict(orient='records'))
    except Exception as e:
        output = str(e)
    return output


if __name__ == '__main__':
    app.run()