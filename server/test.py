import json, requests, xmltodict
from xml.etree.ElementTree import fromstring


user_agent = 'phishtank/arunsura'
HEADERS = { 'User-Agent' : user_agent}
url = 'https://www.gooasdgle.com/'
PARAMS = {'format':'json','url': url, 'app_key':'64a9b1e127ea901f37e4af6ec90a178e3c11af86946ad2b48077462da20296a5'}
r = requests.request('POST','http://checkurl.phishtank.com/checkurl/index.php', headers=HEADERS, params=PARAMS)
json_data = json.dumps(xmltodict.parse(r.text))
res = json.loads(json_data)
print(res['response']['results']['url0']['valid'])