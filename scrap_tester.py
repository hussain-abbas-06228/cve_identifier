import requests
from bs4 import BeautifulSoup

URL = "https://nvd.nist.gov/vuln/detail/CVE-2013-2566"
headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36"}
page = requests.get(URL,headers=headers)
soup = BeautifulSoup(page.content, 'html.parser')
results = soup.find(id='vulnTechnicalDetailsDiv')
cwe = results.text
# remove spaces from cwe
cwe = cwe.replace(" ", "")
# split where newline
cwe = cwe.splitlines()
# remove empty strings
cwe = list(filter(None, cwe))
cweId = cwe[4]
cweName = cwe[5]
print(cweId)
print(cweName)

# make the new link
cweLink = "https://cwe.mitre.org/data/definitions/" + cweId + ".html"


# print(results.prettify())