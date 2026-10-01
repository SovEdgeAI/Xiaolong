import socket
import json
import os
import numpy as np
import joblib
import warnings

# Suppress warnings
warnings.filterwarnings('ignore')

def print_model_prediction(logistic_regression_prediction, naive_bayes_prediction):
    print("\nLogistic Regression Prediction:", logistic_regression_prediction)
    print("Naive Bayes Prediction:", naive_bayes_prediction)

def print_model_probabilities(logistic_regression_probabilities, naive_bayes_probabilities):
    print("\nLogistic Regression Probabilities:", logistic_regression_probabilities)
    print("Naive Bayes Probabilities:", naive_bayes_probabilities)

# Set up the server socket
server_ip = "0.0.0.0"
# Overridable so this can run alongside another deployment already on 5500.
server_port = int(os.environ.get('PREDICT_PORT', 5500))

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((server_ip, server_port))
server_socket.listen(1)

print(f"Server listening on {server_ip}:{server_port}")

# Load the pre-trained models and scaler
logistic_regression_model = joblib.load('LogisticRegression.joblib')
naive_bayes_model = joblib.load('GaussianNB.joblib')
scaler_train = joblib.load('scaler.joblib')

def handle_request(client_socket):
    try:
        # Read the request headers and body
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = client_socket.recv(4096)
            if not chunk:
                raise ValueError("connection closed before headers were complete")
            request += chunk
        headers, body = request.split(b"\r\n\r\n", 1)

        # Headers and body often arrive in separate segments; read the body to
        # Content-Length or json.loads sees an empty string (same fix as
        # approach1/ML/MLmodule.py).
        length = 0
        for line in headers.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                length = int(value.strip())
        while len(body) < length:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            body += chunk

        # Decode the JSON body
        json_data = body.decode('utf-8')
        print("Received data:", json_data)
        payload = json.loads(json_data)
        print("Payload:", payload)

        # Extract the 'data' key from the payload
        input_data = payload.get('data')

        if not input_data:
            raise ValueError("No 'data' key found in the received JSON")

        # Convert the input data to a NumPy array
        input_array = np.array(input_data)

        # Use the loaded scaler to transform the input data
        scaled_input_data = scaler_train.transform(input_array.reshape(1, -1))

        # Make predictions using each model
        logistic_regression_prediction = logistic_regression_model.predict(scaled_input_data)
        naive_bayes_prediction = naive_bayes_model.predict(scaled_input_data)

        # Make probability predictions using each model
        logistic_regression_probabilities = logistic_regression_model.predict_proba(scaled_input_data)
        naive_bayes_probabilities = naive_bayes_model.predict_proba(scaled_input_data)

        # Print predictions and probabilities for debugging
        print_model_prediction(logistic_regression_prediction, naive_bayes_prediction)
        print_model_probabilities(logistic_regression_probabilities, naive_bayes_probabilities)

        # Prepare the response
        response = {
            "logistic_regression": {
                "prediction": int(logistic_regression_prediction[0]),
                "probabilities": logistic_regression_probabilities.tolist()
            },
            "naive_bayes": {
                "prediction": int(naive_bayes_prediction[0]),
                "probabilities": naive_bayes_probabilities.tolist()
            }
        }

        # Send the response back to the client
        response_body = json.dumps(response)
        response_header = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n".format(len(response_body))
        client_socket.sendall(response_header.encode('utf-8') + response_body.encode('utf-8'))

    except Exception as e:
        print(f"Error processing data: {e}")
        response = {"status": "error", "message": str(e)}

        try:
            # Send an error response back to the client
            error_body = json.dumps(response)
            error_header = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n".format(len(error_body))
            client_socket.sendall(error_header.encode('utf-8') + error_body.encode('utf-8'))

        except (BrokenPipeError, ConnectionResetError) as e:
            print(f"Error sending error response to the client: {e}")

    finally:
        # Close the client socket
        client_socket.close()

# Serve continuously. The accept loop was commented out upstream, which made the
# process exit after a single prediction instead of staying up as a service.
try:
    while True:
        # Wait for a connection from the client
        client_socket, client_address = server_socket.accept()
        print(f"Accepted connection from {client_address}", flush=True)
        handle_request(client_socket)
except KeyboardInterrupt:
    print("Shutting down.")
finally:
    # Close the server socket
    server_socket.close()
