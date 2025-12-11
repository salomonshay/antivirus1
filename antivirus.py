import requests
import os
import time


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
    try:
        with open(file_path, "rb") as file:
            files = {"file": (file_path, file)}
            response = requests.post(url, files=files, headers=headers)
            
            if response.status_code == 200:
                print("File uploaded successfully!")
                analysis_id = response.json().get("data", {}).get("id")
                print(f"Analysis ID: {analysis_id}")
                return analysis_id
            else:
                print(f"Error uploading file: {response.status_code}")
                print(response.json()) 
                return None
    except Exception as e:
        print(f"Exception during upload: {e}")
        return None
def scan_directory(directory_path):
    results = []
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Scanning: {file_path}")
            analysis_id = scan_file(file_path)
            time.sleep(15)
            
            if analysis_id:
                response = get_res(analysis_id)
                if response:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("stats")
                    results.append({
                        "file": file_path,
                        "analysis_id": analysis_id,
                        "stats": stats
                    })
                    print(f"Stats: {stats}\n")
                else:
                    print(f"Failed to scan file: {file_path}\n")
    
    return results

def get_res(analysis_id2use):
    if analysis_id2use:
        result_url = urlresult + analysis_id2use
        max_attempts = 30  
        for attempt in range(max_attempts):
            Fin_response = requests.get(result_url, headers=headers)
            data = Fin_response.json()
            status = data.get("data", {}).get("attributes", {}).get("status")
            
            if status == "completed":
                return Fin_response
            
            print(f"Status: {status}, attempt {attempt + 1}/{max_attempts}")
            time.sleep(2) 
        
        print(f"Timeout: סריקה של {analysis_id2use} לא הסתיימה בזמן")
        return None
    else:
        print("No analysis ID provided.")
        return None

#נסיון סריקת קובץ בודד
analysis_id = scan_file(file_path)
response = get_res(analysis_id)
print("-----------------------------------------------")
data = response.json()
stats = data.get("data", {}).get("attributes", {}).get("stats")
print(stats)
print("-----------------------------------------------")

# נסיון סריקת תיקיה שלמה
print(scan_directory(dir_path))