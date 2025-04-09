# === START: pem_to_blob.py (Corrected Version V3) ===
import sys
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Windows CryptoAPI constants
PUBLICKEYBLOB_TYPE = 0x06
CUR_BLOB_VERSION = 0x02
CALG_RSA_KEYX = 0x0000a400 # Key exchange algorithm
RSA1_MAGIC = 0x31415352   # "RSA1"

if len(sys.argv) != 2:
    print(f"Usage: python {os.path.basename(__file__)} <public_key.pem>", file=sys.stderr)
    sys.exit(1)

pem_file = sys.argv[1]

if not os.path.exists(pem_file):
    print(f"Error: Input PEM file not found: {pem_file}", file=sys.stderr)
    sys.exit(1)

try:
    with open(pem_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Input file is not a valid RSA public key PEM.")

    pub_numbers = public_key.public_numbers()
    modulus = pub_numbers.n
    exponent = pub_numbers.e

    if exponent != 65537:
         print(f"Error: This script currently requires RSA exponent 65537 (0x10001). Found: {exponent}", file=sys.stderr)
         sys.exit(1)

    key_len_bits = public_key.key_size
    modulus_bytes = modulus.to_bytes((key_len_bits + 7) // 8, byteorder='little')

    # Construct the BLOB in memory
    blob = bytearray()
    blob.append(PUBLICKEYBLOB_TYPE)     # bType
    blob.append(CUR_BLOB_VERSION)       # bVersion
    blob.extend((0).to_bytes(2, 'little')) # reserved = 0
    blob.extend(CALG_RSA_KEYX.to_bytes(4, 'little')) # aiKeyAlg = CALG_RSA_KEYX
    blob.extend(RSA1_MAGIC.to_bytes(4, 'little'))       # magic = "RSA1"
    blob.extend(key_len_bits.to_bytes(4, 'little'))   # bitlen
    blob.extend((65537).to_bytes(4, byteorder='little')) # pubexp
    blob.extend(modulus_bytes) # modulus

    # --- Format JUST the byte values as a comma-separated string ---
    # Print the first byte without a leading comma
    if len(blob) > 0:
        print(f"    0x{blob[0]:02X}", end="") # Indent for structure

    # Iterate and format remaining bytes with leading comma and potential newline
    for i in range(1, len(blob)):
        print(",", end="") # Comma *before* the byte value
        # Add newline every 16 bytes for readability
        if i % 16 == 0:
             print("\n    ", end="") # Indent new line
        else:
            print(" ", end="") # Add space after comma otherwise
        # Print byte as hex
        print(f"0x{blob[i]:02X}", end="")

    # Print a final newline for cleanliness AFTER the last byte
    print() # Ensures the closing }; is on its own line in the C++ file

except Exception as e:
    print(f"\nError during key conversion: {e}", file=sys.stderr)
    sys.exit(1)

# === END: pem_to_blob.py (Corrected Version V3) ===
