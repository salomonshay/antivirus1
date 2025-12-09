import requests
API_KEY = "5fc212ec528029c016b52e069c68cd09213922269445a113c0d2417fd7830221"
url = "https://www.virustotal.com/api/v3/files"
urlresult = "https://www.virustotal.com/api/v3/analyses/id"
file_path = ""
headers = {
    "x-apikey": API_KEY,
    "content-type": "multipart/form-data",
    "accept": "application/json",
}
def scan_file(file_path):
    with open(file_path,"rb") as file:
        files = {"file":(file_path,file)}
        response = requests.post(url, files = files, headers=headers)
        print(response.json())
        if response.status_code == 200:
            print("File uploaded successfully!")
            analysis_id = response.json().get("data", {}).get("id")
            print(f"Analysis ID: {analysis_id}")
        else:
            print(f"Error uploading file: {response.status_code}")
            print(response.json())
            return response.json()

def get_res():
    Fin_response = requests.get(urlresult, headers=headers)
print(scan_file(file_path))
print(get_res())
