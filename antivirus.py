import requests
import os


API_KEY = "5fc212ec528029c016b52e069c68cd09213922269445a113c0d2417fd7830221"
url = "https://www.virustotal.com/api/v3/files"
urlresult = "https://www.virustotal.com/api/v3/analyses/"
result_url = ""
file_path = r"C:\Users\Admin\Desktop\shay\academia\antivirus\antivirus1\saw.txt"
dir_path = r"C:\Users\Admin\Desktop\shay\academia\antivirus\antivirus1"
print(os.path.isfile(file_path))



headers = {
    "x-apikey": API_KEY,
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

def scan_directory(directory_path):
    for root , dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
    print("File path: {0}\nResult: {1}\n\n".format(file_path, scan_file(file_path)))

def get_res(analysis_id):
    if analysis_id:
        result_url = urlresult + analysis_id
        Fin_response = requests.get(result_url, headers=headers)
        return Fin_response
    else:
        print("No analysis ID provided.")
        return None

def printdata_of_one_file(analysis_id):
    print()

analysis_id = scan_file(file_path)
response = get_res(analysis_id)
data = response.json()
stats = data.get("data", {}).get("attributes", {}).get("stats")
print(stats)
print(scan_directory(dir_path))