import requests
import json
import urllib.parse
import numpy as np
import joblib
import warnings
import time
import os
import math
# Suppress warnings
warnings.filterwarnings('ignore')

# Was hardcoded to the original lab machine (10.102.196.198). Defaults to the
# local flow API; override with FLOW_API to point elsewhere.
FLOW_API = os.environ.get('FLOW_API', 'http://127.0.0.1:23500')

# Load the pre-trained models and scaler
logistic_regression_model = joblib.load('LogisticRegression.joblib')
naive_bayes_model = joblib.load('GaussianNB.joblib')
scaler_train = joblib.load('scaler.joblib')

def handle_request(input_data):
    input_array = np.array(input_data)
    scaled_input_data = scaler_train.transform(input_array.reshape(1, -1))

    logistic_regression_prediction = logistic_regression_model.predict(scaled_input_data)
    naive_bayes_prediction = naive_bayes_model.predict(scaled_input_data)

    return logistic_regression_prediction, naive_bayes_prediction

def fetch_flows():
    """Returns the current flow list, or None if the API is briefly unavailable.

    The detector used to call requests.get() bare, so a single refused
    connection (e.g. the flow API being restarted) raised ConnectionError and
    killed the process for good - detection then stayed off silently, with the
    last log lines still looking like normal output.
    """
    try:
        response = requests.get(f'{FLOW_API}/unidirectionalFlows', timeout=10)
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as e:
        print(f"flow API unavailable, retrying in 5s: {e.__class__.__name__}: {e}", flush=True)
        return None


while True:
    data = fetch_flows()
    if data is None:
        time.sleep(5)
        continue

    for i in data:
        input_data = [
            i['fwdFlow']['protocol'], 
            i['fwdFlow']['durationInMicroseconds'], 
            i['fwdFlow']['packets'], 
            i['bwdFlow']['packets'], 
            i['fwdFlow']['bytes'], 
            i['bwdFlow']['bytes'], 
            i['flowBytesPerSecond'], 
            i['flowPacketsPerSecond'], 
            i['bwdPacketLengthMax'], 
            i['bwdPacketLengthMin']
        ]
        
        # A flow whose counters never advanced (e.g. while the switch and the
        # controller disagree about an entry) yields NaN rates. One such record
        # must not take the whole detector down with a sklearn ValueError.
        # The API returns protocol as a string; sklearn coerces it, so do the same.
        try:
            features = [float(v) for v in input_data]
        except (TypeError, ValueError):
            features = None
        if features is None or not all(math.isfinite(v) for v in features):
            print(f"skipping {i['_id']}: non-finite feature in {input_data}")
            continue

        lr, nb = handle_request(input_data)
        print(f"LR: {lr}, NB: {nb}, ID: {i['_id']}")

        # Construct the URL with _id as a query parameter
        put_url = f"{FLOW_API}/unidirectionalFlow/{urllib.parse.quote(i['fwdFlow']['srcIp'])}<->{urllib.parse.quote(i['fwdFlow']['dstIp'])}<->{urllib.parse.quote(str(i['fwdFlow']['protocol']))}"
        print(put_url)
        
        # Prepare the PUT request body
        data = {
            'nbPrediction': int(nb[0]), 
            'lrPrediction': int(lr[0])
        }
        
        # Use put_url instead of url for PUT request
        try:
            response = requests.put(put_url, json=data, timeout=10)
        except requests.RequestException as e:
            # Losing one vote is fine; losing the detector is not.
            print(f"PUT failed for {i['_id']}: {e.__class__.__name__}", flush=True)
            continue

        # Print the response from the server
        print(f"Status Code: {response.status_code}")
        print(f"Response Body: {response.text}")

    time.sleep(5)
