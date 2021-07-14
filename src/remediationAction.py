import json
import os
import urllib3
import boto3

http = urllib3.PoolManager()

mainUrl = "https://cloudone.trendmicro.com/api/"
headers = {
    'api-version': 'v1',
    'Content-Type': 'application/json',
    'api-secret-key': os.environ["APIKEY"]
}

def lambda_handler(event, context):
    if(event['detail']['actionName'] == 'ApplicationBlockRule'):
        for finding in event['detail']['findings']:
            if(finding['GeneratorId'] == 'trend-micro-workload-security-applicationcontrol'):
                productARN = finding['ProductArn']
                findingId = finding['Id']
                hostID = finding['ProductFields']['trend-micro:HostID']
                processHash = finding['ProductFields']['trend-micro:SHA256']
                searchSoftwareChanges(hostID, processHash, findingId, productARN)

def searchSoftwareChanges(computerID, sha256, findingId, productARN):
    url=mainUrl+"softwarechanges/search"
    print("HostID", computerID)
    print("SHA256", sha256)
    payload = json.dumps({"searchCriteria": [{"fieldName": "computerID","numericTest": "equal","numericValue": computerID},{"fieldName": "sha256","stringTest": "equal","stringValue": sha256}]})

    r = http.request("POST", url, headers=headers, body=payload)
    response = json.loads(r.data.decode('utf-8'))
    if(len(response['softwareChanges'])>0):
        changeProcessID = response['softwareChanges'][0]['ID']
        blockExecution(changeProcessID)
        updateFinding(findingId, productARN)
    else:
        if(getAgentConfiguraton(computerID, sha256)):
            updateFinding(findingId, productARN)

def blockExecution(changeProcessID):
    url = mainUrl+"softwarechanges/review"
    
    payload = json.dumps({
        "softwareChangeIDs": [
            changeProcessID,
        ],
        "action": "block"
    })
    r = http.request("POST", url, headers=headers, body=payload)
    response = json.loads(r.data.decode('utf-8'))
    print(response)
    return True

def updateFinding(findingId, productARN):
    securityhub = boto3.client("securityhub")
    response = securityhub.batch_update_findings(
        FindingIdentifiers=[{
            'Id': findingId,
            'ProductArn': productARN
        }], 
        Severity={ 
            'Label': 'INFORMATIONAL', 
        }
    ) 
    print(response)

def getAgentConfiguraton(computerID, sha256):
    url = mainUrl+"computers/search?expand=applicationControl"
    payload = json.dumps({
        "searchCriteria": [{"fieldName": "computerID","idValue": computerID,"idTest": "equal"}]})
    r = http.request("POST", url, headers=headers, body=payload)
    response = json.loads(r.data.decode('utf-8'))
    rulesetID = response["computers"][0]['applicationControl']['rulesetID']
    urlR = mainUrl+"rulesets/{}/rules/search".format(rulesetID)
    payloadR = json.dumps({
        "searchCriteria": [{"fieldName": "sha256","stringTest": "equal","stringValue": sha256},{"fieldName": "action","choiceTest": "not-equal","choiceValue": "block"}]
    })
    r = http.request("POST", urlR, headers=headers, body=payloadR)
    response = json.loads(r.data.decode('utf-8'))
    if(len(response['applicationControlRules']) > 0):
        ruleID = response['ID']
        url=mainUrl+"rulesets/{}/rules/{}".format(rulesetID, ruleID)
        payload=json.dumps({"action": "block"})
        r = http.request("POST", url, headers=headers, body=payload)
        response = json.loads(r.data.decode('utf-8'))
        print(response)
        return True
    else:
        return False