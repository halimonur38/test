import requests
import json

# Set your Nessus API URL
nessus_url = "https://your-nessus-url"

def login(username, password):
    login_url = f"{nessus_url}/session"
    headers = {
        "Content-Type": "application/json",
    }
    data = {
        "username": username,
        "password": password,
    }

    response = requests.post(login_url, headers=headers, data=json.dumps(data))
    if response.status_code not in (200, 201):
        raise Exception("Failed to login, request status code: " + str(response.status_code) + ", check that username/password are correct")

    return json.loads(response.text)["token"]

def logout(token):
    logout_url = f"{nessus_url}/session"
    headers = {
        "Content-Type": "application/json",
        "X-Cookie": f"token={token}",
    }

    response = requests.delete(logout_url, headers=headers)
    if response.status_code not in (200, 401):
        raise Exception("Failed to logout session, request status code: " + str(response.status_code) + ", body=" + response.text)

    return "deleted"

def list_scans(token):
    scans_url = f"{nessus_url}/scans"
    headers = {
        "Content-Type": "application/json",
        "X-Cookie": f"token={token}",
    }

    response = requests.get(scans_url, headers=headers)
    if response.status_code != 200:
        raise Exception("Failed to get scans list, request status code: " + str(response.status_code) + ", body=" + response.text)

    logout(token)

    return json.loads(response.text)

def scan_launch(token, scan_id, targets):
    launch_url = f"{nessus_url}/scans/{scan_id}/launch"
    headers = {
        "Content-Type": "application/json",
        "X-Cookie": f"token={token}",
    }
    data = {}

    if targets and len(targets) > 0:
        targets_arr = [targets]
        data["alt_targets"] = targets_arr

    response = requests.post(launch_url, headers=headers, data=json.dumps(data))
    if response.status_code != 200:
        raise Exception("Failed to launch scan, request status code: " + str(response.status_code) + ", body=" + response.text)

    logout(token)

    return f"Scan launched. Scan UUID: {json.loads(response.text)['scan_uuid']}"

def scan_details(token, scan_id, history_id):
    details_url = f"{nessus_url}/scans/{scan_id}"

    if history_id and len(history_id) > 0:
        details_url += f"?history_id={history_id}"

    headers = {
        "Content-Type": "application/json",
        "X-Cookie": f"token={token}",
    }

    response = requests.get(details_url, headers=headers)
    if response.status_code != 200:
        raise Exception("Failed to get scan details, request status code: " + str(response.status_code) + ", body=" + response.text)

    logout(token)

    return json.loads(response.text)

def scan_status(token, scan_id):
    status_url = f"{nessus_url}/scans/{scan_id}"

    headers = {
        "Content-Type": "application/json",
        "X-Cookie": f"token={token}",
    }

    response = requests.get(status_url, headers=headers)
    if response.status_code != 200:
        raise Exception("Failed to get scan status, request status code: " + str(response.status_code) + ", body=" + response.text)

    logout(token)

    return "Scan status: " + json.loads(response.text)["info"]["status"]

def scan_host_details(token, scan_id, history_id, host_id):
    host_details_url = f"{nessus_url}/scans/{scan_id}/hosts/{host_id}"

    if history_id and len(history_id) > 0:
        host_details_url += f"?history_id={history_id}"

    headers = {
        "Content-Type": "application/json",
        "X-Cookie": f"token={token}",
    }

    response = requests.get(host_details_url, headers=headers)
    if response.status_code != 200:
        raise Exception("Failed to get scan host details, request status code: " + str(response.status_code) + ", body=" + response.text)

    logout(token)

    return json.loads(response.text)

def scan_export(token, scan_id, history_id, export_format, password, chapters):
    export_url = f"{nessus_url}/scans/{scan_id}/export"

    if history_id and len(history_id) > 0:
        export_url += f"?history_id={history_id}"

    headers = {
        "Content-Type": "application/json",
        "X-Cookie": f"token={token}",
    }

    data = {"format": export_format}

    if password and len(password) > 0:
        data["password"] = password

    if chapters and len(chapters) > 0:
        data["chapters"] = chapters

    response = requests.post(export_url, headers=headers, data=json.dumps(data))
    if response.status_code != 200:
        raise Exception("Failed to export scan, request status code: " + str(response.status_code) + ", body=" + response.text)

    logout(token)

    return "Report file id: " + json.loads(response.text)["file"]

def get_report(token, scan_id, file_id):
    report_url = f"{nessus_url}/scans/{scan_id}/export/{file_id}/download"
    
    headers = {
        "Content-Type": "application/json",
        "X-Cookie": f"token={token}",
    }

    response = requests.get(report_url, headers=headers)
    if response.status_code != 200:
        raise Exception("Failed to download report, request status code: " + str(response.status_code) + ", body=" + response.text)

    logout(token)

    with open(f"{file_id}.nessus", "w") as report_file:
        report_file.write(response.text)

    return f"{file_id}.nessus"
def scan_create(token, editor_uuid, name, description, policy, folder, scanner_id, schedule, launch_time, start_time, rules, time_zone, targets, file_targets, emails, acls):
    create_scan_url = f"{nessus_url}/scans"
    
    headers = {
        "Content-Type": "application/json",
        "X-Cookie": f"token={token}",
    }
    
    data = {
        "uuid": editor_uuid,
        "settings": {
            "name": name,
        }
    }
    
    if description and len(description) > 0:
        data["settings"]["description"] = description
    
    if policy and len(policy) > 0:
        data["settings"]["policy_id"] = int(policy)
    
    if folder and len(folder) > 0:
        data["settings"]["folder_id"] = int(folder)
    
    if scanner_id and len(scanner_id) > 0:
        data["settings"]["scanner_id"] = int(scanner_id)
    
    if schedule and len(schedule) > 0:
        data["settings"]["enabled"] = schedule.lower() == "true"
    
    if launch_time and len(launch_time) > 0:
        data["settings"]["launch"] = launch_time
    
    if start_time and len(start_time) > 0:
        data["settings"]["starttime"] = start_time
    
    if rules and len(rules) > 0:
        data["settings"]["rrules"] = rules
    
    if time_zone and len(time_zone) > 0:
        data["settings"]["timezone"] = time_zone
    
    if targets and len(targets) > 0:
        data["settings"]["text_targets"] = targets
    
    if file_targets and len(file_targets) > 0:
        data["settings"]["file_targets"] = file_targets
    
    if emails and len(emails) > 0:
        data["settings"]["emails"] = emails
    
    if acls and len(acls) > 0:
        data["settings"]["acls"] = acls
    
    response = requests.post(create_scan_url, headers=headers, data=json.dumps(data))
    
    if response.status_code != 200:
        raise Exception("Failed to create a scan, request status code: " + str(response.status_code) + ", body=" + response.text)
    
    logout(token)
    
    scan_info = json.loads(response.text)
    scan_id = scan_info["scan"]["id"]
    scan_name = scan_info["scan"]["name"]
    
    return f"Scan created with ID: {scan_id}, Name: {scan_name}"

# Nessus komutlarının işlenmesi
if command == "test-module":
    token = login()
    logout(token)
    demisto.debug(f"Command: {command}")
    demisto.debug(f"Result: {token and len(token) > 0}")
elif command == "nessus-list-scans":
    demisto.results(list_scans(login()))
elif command == "nessus-launch-scan":
    demisto.results(scan_launch(login(), args["scan_id"], args["targets"]))
elif command == "nessus-scan-details":
    demisto.results(scan_details(login(), args["scan_id"], args["history_id"]))
elif command == "nessus-scan-export":
    demisto.results(scan_export(login(), args["scan_id"], args["history_id"], args["format"], args["password"], args["chapters"]))
elif command == "nessus-scan-report-download":
    demisto.results(get_report(login(), args["scan_id"], args["file_id"]))
elif command == "nessus-scan-export-status":
    demisto.results(get_status(login(), args["scan_id"], args["file_id"]))
elif command == "nessus-scan-create":
    demisto.results(scan_create(login(), args["editor"], args["name"], args["description"], args["policyId"],
                               args["folderId"], args["scannerId"], args["schedule"], args["launch"], args["startTime"],
                               args["rules"], args["timeZone"], args["targets"], args["fileTargets"], args["emails"],
                               args["acls"]))
elif command == "nessus-get-scans-editors":
    demisto.results(get_editors(login()))
elif command == "nessus-scan-status":
    demisto.results(scan_status(login(), args["scan_id"]))
elif command == "nessus-scan-host-details":
    demisto.results(scan_host_details(login(), args["scan_id"], args["history_id"], args["host_id"]))
elif command == "get-completed-scans":
    completed_scans = get_completed_scans(login())
    hosted_vulnerabilities = []

    for scan in completed_scans:
        if scan["Status"] == "completed":
            scan_details = scan_details(login(), scan["ID"], None)
            if "EntryContext" in scan_details and "NessusScan" in scan_details["EntryContext"] and len(
                    scan_details["EntryContext"]["NessusScan"]) > 0:
                hosted_vulnerabilities_list = []
                for folder in scan_details["EntryContext"]["NessusScan"][0]["NessusFolder"]:
                    if "UUID" in folder:
                        scan_host_details = scan_host_details(login(), scan["ID"], None, folder["ID"])
                        hosted_vulnerabilities_list.append({"Host": folder["Name"], "Vulnerabilities": scan_host_details["Vulnerability"]})
                hosted_vulnerabilities.append({"UUID": scan["UUID"], "HostedVulnerabilities": hosted_vulnerabilities_list})

    demisto.results({
        "Type": 1,
        "Contents": hosted_vulnerabilities,
        "ContentsFormat": 6,
        "HumanReadable": "Hosted Vulnerabilities: " + json.dumps(hosted_vulnerabilities)
    })
elif command == "get-hosted-vulnerabilities":
    hosted_vulnerabilities = []
    completed_scans = get_completed_scans(login())
    for scan in completed_scans:
        hosts = scan["Endpoint"]
        for host in hosts:
            vulnerabilities = get_hosted_vulnerabilities(login(), scan["ID"], host["ID"])
            hosted_vulnerabilities.append(vulnerabilities)

    demisto.results({
        "Type": 1,
        "Contents": hosted_vulnerabilities,
        "ContentsFormat": 6,
        "HumanReadable": "Hosted Vulnerabilities: " + json.dumps(hosted_vulnerabilities)
    })
