import requests

def mitigate(flow_id, ids):
    # Extract the IP address that matches 10.45.0.0/16
    src = flow_id.split("<->")[0]
    dst = flow_id.split("<->")[1]
    print(src)
    print(dst)
    
    delete_ids = [id for id in ids if src in id]
    print(delete_ids)

    for id in delete_ids:
        delete_url = f"http://127.0.0.1:23000/unidirectionalFlows/{id}"
        response = requests.delete(delete_url)
        if response.status_code == 200:
            print(f"Flow {id} deleted successfully")
        else:
            print(f"Failed to delete flow {id}: {response.text}")

    # Block that IP 
    block_url = "http://127.0.0.1:23000/blocked-ip"
    data = {"ip": src}

    response = requests.post(block_url, json=data, headers={'Content-Type': 'application/json'})

    if response.status_code == 200:
        print(f"IP {src} blocked successfully")
    else:
        print(f"Failed to block IP {src}: {response.text}")
