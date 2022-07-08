import json
import boto3
from botocore.exceptions import ClientError
import urllib3
from urllib.parse import urlencode
import os
import base64
import pandas as pd
from datetime import date
import time


def lambda_handler(event, context):
    
    # Create directories
    os.chdir('/tmp')
    if not os.path.exists(os.path.join('zipped')):
        os.makedirs('zipped')
    if not os.path.exists(os.path.join('unzipped')):
        os.makedirs('unzipped')
    
    #Qualtrics Parameters
    dataCenter = "sjc1"
    surveyId = "<insert_survey_id>"
    
    #AWS Parameters
    
    #DEV BUCKET AND PREFIX!
    bucket = '<insert_bucket_name>'
    bucket_prefix = 'qualtrics_poc/'
    
    fileName = surveyId + "_" + str(date.today())
    target_format = ".csv"
    zip_path = '/tmp/zipped/' + fileName + ".zip"
    save_path = '/tmp/unzipped/' + fileName + target_format
    
    
    http = urllib3.PoolManager()
    
    def get_secret(secret_key):
        
        secret_name = "<insert_secret_ARN>"
        region_name = "us-east-1"
        
        # Create a Secrets Manager client
        session = boto3.session.Session()
        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )
    
        response = client.get_secret_value(
            SecretId=secret_name
            )
             
        secret = json.loads(response['SecretString'])
        
        return secret[secret_key]
    
    # REPLACE PLAINTEXT IDS WITH SECRETS MANAGER API CALL!!
    
    #clientId = get_secret('<SECRET_MANAGER_CLIENT_ID_KEY>')
    clientId = "<qualtrics_API_clientId>"
    
    #clientSecret = get_secret('<SECRET_MANAGER_CLIENT_SECRET_KEY>')
    clientSecret = "<qualtrics_API_clientSecret>"

    
    def getToken():
        baseUrl = "https://{0}.qualtrics.com/oauth2/token".format(dataCenter) 
        encoded_args = urlencode({'grant_type': 'client_credentials','scope': 'read:survey_responses'})
        fullUrl = baseUrl + "?" + encoded_args
        creds = "{0}:{1}".format(clientId,clientSecret)
        header_text = "Basic " + base64.b64encode(creds.encode("utf-8")).decode("utf-8")
        headers = {
                "Authorization": header_text
                }
        
        r = http.request('POST', fullUrl, headers=headers)
        return json.loads(r.data)['access_token']

    bearerToken = getToken()
    print("Bearer Token: " + bearerToken)

    
    def startResponseExport():
        baseUrl = "https://{0}.qualtrics.com/API/v3/surveys/{1}/export-responses".format(dataCenter, surveyId)
        data = {"format":"csv", "compress":True, "useLabels":True}
        encoded_data = json.dumps(data).encode('utf-8')
        headers = {
        "Authorization":"Bearer " + bearerToken,
        "Content-Type":"application/json"
        }
        r = http.request('POST', baseUrl, body = encoded_data, headers=headers)
        progressId = json.loads(r.data)['result'].get('progressId')
        return progressId
    
    exportProgressId = startResponseExport()
    print("Export Progress ID: " + exportProgressId)


    def getResponseExportProgress():
        baseUrl = "https://{0}.qualtrics.com/API/v3/surveys/{1}/export-responses/{2}".format(dataCenter, surveyId, exportProgressId)
        headers = {
        "Authorization":"Bearer " + bearerToken,
        "Content-Type":"application/json"
        }
        r = http.request('GET', baseUrl, headers=headers)

        if json.loads(r.data)['result'].get('percentComplete') != 100.0 and json.loads(r.data)['meta'].get('httpStatus') ==  '200 - OK':
            print("File not ready, waiting 3 seconds...")
            print(json.loads(r.data))
            time.sleep(3)
            r = http.request('GET', baseUrl, headers=headers)
        
        
        fileId = json.loads(r.data)['result'].get('fileId')
        return fileId
    
    fileId = getResponseExportProgress()
    print("File ID: " + str(fileId))    
    
    
    def getResponseExportFile():
        baseUrl = "https://{0}.qualtrics.com/API/v3/surveys/{1}/export-responses/{2}/file".format(dataCenter, surveyId, fileId)
        headers = {
        "Authorization":"Bearer " + bearerToken,
        "Content-Type":"application/json"
        }
        r = http.request('GET', baseUrl, headers=headers, preload_content=False)
        
        with open(zip_path, 'wb') as out:
            while True:
                data = r.read()
                if not data:
                    break
                out.write(data)
        
        r.release_conn()
    
    getResponseExportFile()
    
    def unzipToCsv():
        # The first three rows in a Qualtrics export are all headers, so drop the 2 you don't want
        # Unzip and read into dataframe
       
        df = pd.read_csv(zip_path, compression = 'zip', skiprows= (0,2))
        
        # Save as a CSV while dropping the pandas index
        df.to_csv(save_path, index=False)
    
    unzipToCsv()
    
    def sendToS3():
        # Send the file to S3
        s3 = boto3.client('s3')
        
        with open(save_path,"rb") as f:
            s3.upload_fileobj(f, bucket, bucket_prefix+fileName+target_format)
        print("File uploaded to S3 bucket: " + bucket + "/" + bucket_prefix)
    
    sendToS3()
