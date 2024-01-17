import hashlib
import base64
from Crypto.Hash import BLAKE2b, RIPEMD160, SHA384, SHA3_256, SHA3_384
from Crypto.Hash import Whirlpool as Whirlpool_crypto


def main():
    # Prompt the user to input the encoded key
    encoded_key = input("Enter the encoded key: ").strip()

    # Define a list of possible algorithms and decodings
    algorithms = [
        {"Name": "MD5 Base64", "HashFunc": hashlib.md5,
            "DecodeFunc": base64.b64decode},
        {"Name": "SHA-1 Base64", "HashFunc": hashlib.sha1,
            "DecodeFunc": base64.b64decode},
        {"Name": "SHA-224 Base64", "HashFunc": hashlib.sha224,
            "DecodeFunc": base64.b64decode},
        {"Name": "SHA-256 Base64", "HashFunc": hashlib.sha256,
            "DecodeFunc": base64.b64decode},
        {"Name": "SHA-512 Base64", "HashFunc": hashlib.sha512,
            "DecodeFunc": base64.b64decode},
        {"Name": "BLAKE2b-512 Hex",
            "HashFunc": BLAKE2b.new(digest_bits=512), "DecodeFunc": bytes.fromhex},
        {"Name": "RIPEMD-160 Hex", "HashFunc": RIPEMD160.new(),
         "DecodeFunc": bytes.fromhex},
        {"Name": "SHA3-224 Hex", "HashFunc": SHA3_224.new(),
         "DecodeFunc": bytes.fromhex},  # Corrected SHA3-224
        {"Name": "SHA-384 Base64", "HashFunc": SHA384.new(),
         "DecodeFunc": base64.b64decode},
        {"Name": "SHA3-256 Hex", "HashFunc": SHA3_256.new(),
         "DecodeFunc": bytes.fromhex},
        {"Name": "SHA3-384 Hex", "HashFunc": SHA3_384.new(),
         "DecodeFunc": bytes.fromhex},
        {"Name": "SHA-384 Hex", "HashFunc": SHA384.new(), "DecodeFunc": bytes.fromhex},
        {"Name": "SHA3-256 Hex", "HashFunc": SHA3_256.new(),
         "DecodeFunc": bytes.fromhex},
        {"Name": "SHA3-384 Hex", "HashFunc": SHA3_384.new(),
         "DecodeFunc": bytes.fromhex},
        {"Name": "SHA3-512 Hex",
            "HashFunc": SHA3_384.new(digest_bits=512), "DecodeFunc": bytes.fromhex},
        {"Name": "BLAKE2s-256 Hex",
            "HashFunc": BLAKE2b.new(digest_bits=256), "DecodeFunc": bytes.fromhex},
        {"Name": "BLAKE2s-256 Base64",
            "HashFunc": BLAKE2b.new(digest_bits=256), "DecodeFunc": base64.b64decode},
        {"Name": "Whirlpool Hex", "HashFunc": Whirlpool_crypto.new(),
         "DecodeFunc": bytes.fromhex},
        # Add more algorithms and decodings as needed
    ]

    # Decode the encoded key once for all algorithms
    for algo in algorithms:
        try:
            decoded_bytes = algo["DecodeFunc"](encoded_key)
            algo["DecodedBytes"] = decoded_bytes
        except Exception as e:
            print(f"Error decoding key for {algo['Name']}: {e}")
            exit(1)

    # Iterate over each algorithm and compare the decoded key
    for algo in algorithms:
        # Hash the decoded key
        hasher = algo["HashFunc"]()
        hasher.update(algo["DecodedBytes"])
        hashed = hasher.digest()

        # Compare with the stored hash
        stored_hash = base64.b64decode(
            "OGE4MWIwZTUzMzgwNjYyOWRlNDZlZDNkOGQ1ZTYwMjFiNGU1MTRkNw==")

        # Compare with the decoded stored hash
        if stored_hash == hashed:
            print(f"Hashes match for {algo['Name']}. Content is valid.")
            return

    # No matches found
    print("Hashes do not match in any method. Content is not valid.")


if __name__ == "__main__":
    main()
