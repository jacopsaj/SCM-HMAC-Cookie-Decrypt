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

# Panorama API Variables
HOSTNAME = "Host/IP"
API_KEY = "API-Key"
TEMPLATE_NAME = "Template-Name"
CERTIFICATE_NAME = "Cert-Name"
VERIFY_XPATH = f"/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='{TEMPLATE_NAME}']/config/shared/certificate/entry[@name='{CERTIFICATE_NAME}']"

# File Extraction Variables
WORKING_DIR = os.path.dirname(os.path.realpath(__file__))
P12_FILE = "Exported-Certificate.p12"
PEM_FILE = "bundle.pem"
PASSPHRASE = b"Passphrase" # Requires the password to be in bytes

def extract_certificate():
    print(f"Extracting {P12_FILE} to {PEM_FILE}...")
    
    try:
        # Read encrypted .p12
        with open(os.path.join(WORKING_DIR, P12_FILE), "rb") as f:
            p12_data = f.read()
            
        # Decrypt the .p12
        private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
            p12_data, 
            PASSPHRASE
        )
        
        # Write to new PEM file
        with open(os.path.join(WORKING_DIR, PEM_FILE), "wb") as pem_out:
            # 1. Write the public certificate
            if certificate:
                pem_out.write(certificate.public_bytes(serialization.Encoding.PEM))
            
            # 2. Write the private key (unencrypted)
            if private_key:
                pem_out.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
                
            # 3. Write any intermediate chain certificates if present
            if additional_certs:
                for cert in additional_certs:
                    pem_out.write(cert.public_bytes(serialization.Encoding.PEM))
                    
        print("Extraction successful.\n")
        return True
        
    except FileNotFoundError:
        print(f"Error: Could not find '{P12_FILE}'.")
        return False
    except ValueError as e:
        print(f"Decryption Error: {e} (Check your PASSPHRASE)")
        return False
    except Exception as e:
        print(f"An unexpected extraction error occurred: {e}")
        return False

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
            print(f"{CERTIFICATE_NAME} successfuly uploaded.")
        else:
            print(f"There was an error uploading {CERTIFICATE_NAME}. Please try again.")
            print("Response Body:")
            print(response.text)
            
    except requests.exceptions.RequestException as e:
        print(f"Connection Error: {e}")

def main():
    # 1. Extract the bundle using Python
    if not extract_certificate():
        return  

    # 2. Upload to Panorama
    url = f"https://{HOSTNAME}/api/"

    params = {
        "type": "import",
        "category": "certificate",
        "format": "pem",
        "certificate-name": CERTIFICATE_NAME,
        "target-tpl": TEMPLATE_NAME,
        "key": API_KEY
    }

    print(f"Uploading {PEM_FILE} to {HOSTNAME}...")

    try:
        with open(os.path.join(WORKING_DIR, PEM_FILE), "rb") as cert_file:
            files = {"file": (os.path.join(WORKING_DIR, PEM_FILE), cert_file)}
            
            response = requests.post(url, params=params, files=files, verify=False)

            if 'status="success"' in response.text.lower():
                # Verify cert upload
                verify_certificate()
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
