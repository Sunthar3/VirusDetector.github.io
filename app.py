from flask import Flask,request,render_template,redirect,url_for
import os
import requests
import json
import time

API_KEY = 'bed41aa210a324a30c2839b2299e2ecb43be863543c02a09c4c198470aec743c'

app=Flask(__name__)

flag=[1]

def pred(fname):
    # Open the file in binary mode
    with open(fname, 'rb') as file:
        # Create a multipart file object
        files = {'file': file}

        # Make a POST request to the VirusTotal API to scan the file
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        parameters = {'apikey': API_KEY}
        response = requests.post(url, files=files, params=parameters)

        # Get the response in JSON format
        json_response = response.json()

        # Check if the scan was successful
        if response.status_code == 200 and json_response['response_code'] == 1:
            # Get the scan ID
            scan_id = json_response['scan_id']
            print(f"File has been successfully submitted for scanning. Scan ID: {scan_id}")
            print("You can check the scan report later using the scan ID.")

            # Retrieve the scan results after a brief delay
            time.sleep(15)  # Adjust the delay as needed
            url = f'https://www.virustotal.com/vtapi/v2/file/report?apikey={API_KEY}&resource={scan_id}'
            response = requests.get(url)
            json_response = response.json()

            # Check if the scan results are available
            if response.status_code == 200 and json_response['response_code'] == 1:
                # Get the scan results
                scan_results = json_response['scans']
                #for antivirus, result in scan_results.items():
                #    print(f"{antivirus}: {result['result']}")
                scan_results_list = list(scan_results.items())
                mydict=scan_results_list[6][1]
                print(mydict['result']) #result by McAfee
                flag[0]=0
                return mydict['result']
                    

            else:
                print("Failed to retrieve scan results. Please try again later.")
                flag[0]=1
                return "Failed to retrieve scan results. Please try again later."
        elif json_response['response_code'] == -1:
            print("File is still being analyzed. Please try again later.")
            flag[0]=1
            return "File is still being analyzed. Please try again later."
        else:
            print("Scan failed. Please check your API key and file name.")
            flag[0]=1
            return "Scan failed. Please check your API key and file name."



@app.route('/res_pred', methods=['GET','POST'])
def respred():
    if request.method == 'POST':  
        f = request.files['file']
        file_path = os.path.join('uploads',f.filename)
        f.save(file_path)  
        print(file_path)
        result=pred(str(file_path))
        os.remove(file_path)
        if(result != "None" and flag[0] != 1) :
            result="Detected : "+result

        if(result == "None"):
            result="Not Detected"
        return render_template("virus_detection2.html",res=result) 

@app.route('/')
def home():
    return render_template("virus_detection.html",res="")

if __name__=="__main__":
    app.run()
