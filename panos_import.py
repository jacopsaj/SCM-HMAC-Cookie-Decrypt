import requests
import urllib3
import os
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# CONFIGURATION VARIABLES
# ==========================================
HOSTNAME = "Host/IP"
API_KEY = "API-Key"
TEMPLATE_NAME = "Template-Name"
CERTIFICATE_NAME = "Cert-Name"
VERIFY_XPATH = f"/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='{TEMPLATE_NAME}']/config/shared/certificate/entry[@name='{CERTIFICATE_NAME}']"

WORKING_DIR = os.path.dirname(os.path.realpath(__file__))
P12_FILE = "Exported-Certificate.p12"
PEM_FILE = "bundle.pem"
PASSPHRASE = b"Passphrase" # Requires the password to be in bytes

def extract_certificate():
    print(f"Extracting {P12_FILE} to {PEM_FILE}...")
    pk_string = None
    
    try:
        with open(os.path.join(WORKING_DIR, P12_FILE), "rb") as f:
            p12_data = f.read()
            
        private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
            p12_data, 
            PASSPHRASE
        )
        
        with open(os.path.join(WORKING_DIR, PEM_FILE), "wb") as pem_out:
            if certificate:
                pem_out.write(certificate.public_bytes(serialization.Encoding.PEM))
            
            if private_key:
                pk_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
                pem_out.write(pk_bytes)
                # Save the unencrypted private key to inject via API
                pk_string = pk_bytes.decode('utf-8')
                
            if additional_certs:
                for cert in additional_certs:
                    pem_out.write(cert.public_bytes(serialization.Encoding.PEM))
                    
        print("Extraction successful.\n")
        return True, pk_string
        
    except FileNotFoundError:
        print(f"Error: Could not find '{P12_FILE}'.")
        return False, None
    except ValueError as e:
        print(f"Decryption Error: {e} (Check your PASSPHRASE)")
        return False, None
    except Exception as e:
        print(f"An unexpected extraction error occurred: {e}")
        return False, None

def verify_certificate():
    url = f"https://{HOSTNAME}/api/"
    
    params = {
        "type": "config",
        "action": "get",
        "xpath": VERIFY_XPATH,
        "key": API_KEY
    }

    print(f"Verifying uploaded certificate...")

    try:
        response = requests.get(url, params=params, verify=False)

        if 'status="success"' in response.text.lower():
            print(f"{CERTIFICATE_NAME} successfully uploaded and verified.")
        else:
            print(f"There was an error verifying {CERTIFICATE_NAME}. Please try again.")
            print("Response Body:")
            print(response.text)
            
    except requests.exceptions.RequestException as e:
        print(f"Connection Error: {e}")

def main():
    # Extract the bundle and capture the private key string
    success, pk_string = extract_certificate()
    if not success:
        return  

    url = f"https://{HOSTNAME}/api/"

    # Step 1: Import the Public Certificate Shell
    import_params = {
        "type": "import",
        "category": "certificate",
        "format": "pem",
        "certificate-name": CERTIFICATE_NAME,
        "target-tpl": TEMPLATE_NAME,
        "key": API_KEY
    }

    print(f"Uploading certificate shell to {HOSTNAME}...")

    try:
        with open(os.path.join(WORKING_DIR, PEM_FILE), "rb") as cert_file:
            files = {"file": (os.path.join(WORKING_DIR, PEM_FILE), cert_file)}
            
            response = requests.post(url, params=import_params, files=files, verify=False)

            if 'status="success"' in response.text.lower():
                print("Certificate shell created successfully.")
                
                # Step 2: Inject the Private Key into the shell
                if pk_string:
                    print("Injecting private key into the object...")
                    
                    set_payload = {
                        "type": "config",
                        "action": "set",
                        "xpath": VERIFY_XPATH,
                        "key": API_KEY,
                        "element": f"<private-key>{pk_string}</private-key>"
                    }
                    
                    # Using the 'data' parameter safely URL-encodes all newlines and slashes
                    set_response = requests.post(url, data=set_payload, verify=False)
                    
                    if 'status="success"' in set_response.text.lower():
                        print("Private key injected successfully!\n")
                        verify_certificate()
                    else:
                        print("Error injecting private key:")
                        print(set_response.text)
                else:
                    print("No private key found in bundle to inject.")
            else:
                print(f"There was an error uploading {CERTIFICATE_NAME}. Please try again.")
                print("Response Body:")
                print(response.text)

            # Clean up decrypted PEM file
            print(f"\nFor security - removing temporary file: {PEM_FILE}...")
            cert_file.close()
            try:
                os.remove(os.path.join(WORKING_DIR, PEM_FILE))
                if not os.path.isfile(os.path.join(WORKING_DIR, PEM_FILE)):
                    print(f"Removed {PEM_FILE} successfully.")
            except OSError as e:
                print(f"Warning: Failed to delete {PEM_FILE}. Please manually remove for security. Error: {e}")

    except FileNotFoundError:
        print(f"Error: Could not find '{PEM_FILE}'.")
    except requests.exceptions.RequestException as e:
        print(f"Connection Error: {e}")

if __name__ == "__main__":
    main()
