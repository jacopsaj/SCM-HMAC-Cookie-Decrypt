# SCM-HMAC-Cookie-Decrypt
## Instructions
#### Generate API Key
1. Enter into browser for API Key: https://[PANORAMA_IP_OR_URL]/api/?type=keygen&user=[ADMIN_USERNAME]&password=[ADMIN_PASSWORD]
#### Generate Cert in SCM:
1. Certificate Name: Any-Cert-Name-No-Spaces
2. Common Name: Any-Common-Name
3. Signed By: Root CA <--- Important! Must be signed by a CA.
#### Export Certificate from SCM:
1. Format: Encrypted Private Key and Certificate (PKCS12)
2. Passphrase: MemorablePassPhrase123
#### Change script variables
##### Panorama API Variables
1. HOSTNAME = "Host/IP"
2. API_KEY = "API-Key"
3. TEMPLATE_NAME = "Template-Name"
4. CERTIFICATE_NAME = "Cert-Name"
5. VERIFY_XPATH = f"/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='{TEMPLATE_NAME}']/config/shared/certificate/entry[@name='{CERTIFICATE_NAME}']"
##### File Extraction Variables
1. WORKING_DIR = os.path.dirname(os.path.realpath(__file__))
2. P12_FILE = "Exported-Certificate.p12"
3. PEM_FILE = "bundle.pem"
4. PASSPHRASE = b"Passphrase" # Requires the password to be in bytes
