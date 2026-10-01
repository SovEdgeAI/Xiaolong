import requests
import numpy as np
import json
import os
import time

# URL to get the flows
get_url = "http://127.0.0.1:23000/unidirectionalFlows"

# URL to update the flow
put_url = "http://127.0.0.1:23000/unidirectionalFlow"

# URL to send the flows. Overridable because the packaged MLmodule on 5500 may be
# an older root-owned instance that cannot be restarted without sudo.
post_url = os.environ.get("ML_URL", "http://127.0.0.1:5500")

while True:
    try:
        response = requests.get(get_url, timeout=10)
        if response.status_code == 200:
            flows = response.json()

            for flow in flows:
                # Input data to predict
                data = np.array([[flow['fwdFlow']['protocol'], flow['fwdFlow']['durationInMicroseconds'], flow['fwdFlow']['packets'], flow['bwdFlow']['packets'], flow['fwdFlow']['bytes'], flow['bwdFlow']['bytes'], flow['flowBytesPerSecond'], flow['flowPacketsPerSecond'], flow['bwdPacketLengthMax'], flow['bwdPacketLengthMin']]])

                # Convert NumPy array to list and then to JSON
                data_list = data.tolist()

                # Print the data to ensure it's correct
                print("Sending data:", json.dumps({"data": data_list}))

                try:
                    response = requests.post(post_url, json={"data": data_list}, timeout=10)

                    if response.status_code == 200:
                        response_json = response.json()  # Store the response JSON once to avoid multiple calls

                        print("Data sent successfully")
                        print("Logistic Regression Prediction:", response_json.get('logistic_regression'))
                        print("Naive Bayes Prediction:", response_json.get('naive_bayes'))

                        # Extract only the 'prediction' field from both models
                        MLdata = {
                            "nbPrediction": response_json.get('naive_bayes', {}).get('prediction'),  # Extracts only the number
                            "lrPrediction": response_json.get('logistic_regression', {}).get('prediction')
                        }

                        # Construct the PUT URL
                        flow_url = f"{put_url}/{flow['_id']}"
                        print("Flow URL:", flow_url)
                        print("MLdata:", MLdata)

                        # Update the flow with the prediction
                        flow_response = requests.put(flow_url, data=json.dumps(MLdata), headers={'Content-Type': 'application/json'}, timeout=10)

                        # Print the status code and response content
                        if flow_response.status_code == 200:
                            print("Flow data updated successfully")
                        else:
                            print("Failed to update flow data")
                            print("Status Code:", flow_response.status_code)
                            print("Response Content:", flow_response.text)
                    else:
                        print("Failed to send data")
                        print("Status Code:", response.status_code)
                        print("Response Content:", response.text)
                except requests.exceptions.RequestException as e:
                    print(f"Error communicating with ML module: {e}")

        else:
            print("Failed to retrieve flows")
            print("Status Code:", response.status_code)
            print("Response Content:", response.text)
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to Flow API: {e}")
        print("Retrying in 30 seconds...")

    time.sleep(30)
