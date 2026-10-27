import json
from datetime import datetime, timezone
import argparse

"""
Insecure Certificate Configuration
- Self-Signed: Signed by the server rather than a trusted CA, allowing server impersonation. Please note that this finding may be a false positive if an internal CA is deployed and trusted within the environment.
- Expired: The certificate validity end date has passed, making identity validation impossible.
- Excessive Validity Period: Exceeds industry lifetime limits, increasing risk if a private key is compromised.
- Signature Verification Failure: The certificate signature cannot be validated against a trusted root CA.
- Hostname Mismatch: The certificate common name or subject alternative name does not match the server FQDN, preventing identity authentication and exposing connections to MitM attacks. Please note that this finding may be a false positive if the target was scanned directly by IP address rather than FQDN.
- Improper Key Usage: Key usage or basic constraints are misconfigured, allowing unauthorized certificate applications.

Insecure Protocol Configuration
- Deprecated Protocols (TLS 1.0, TLS 1.1): Supports outdated protocols vulnerable to downgrade and legacy cryptographic attacks.
- Weak Ciphers/Algorithms: Supports deprecated ciphers/algorithms, exposing sessions to collision attacks, plaintext recovery, or session key decryption.
"""

VULNERBLE_PROTOCOLS = ["SSLv2", "SSLv3", "TLS1", "TLS1_1"]
VULNERABLE_CIPHERS = ["cipherlist_NULL", "cipherlist_aNULL", "cipherlist_EXPORT", "cipherlist_LOW", "cipherlist_3DES_IDEA", "cipherlist_OBSOLETED"]
inputfile = "temp.json"

results_self_signed = []
results_expired = []
results_excessive_validity = []
results_signature_verification_failure = []
results_improper_key_usage = []
results_deprecated_protocols = []
results_weak_ciphers = []
results_fs_weak = []


def test_server_defaults(defaults_list, host):
    cert_valid_start = 0
    cert_valid_end = 0
    for default in defaults_list:
        # check CN exists
        if default['id'] == 'cert_commonName':
            if default['severity'] != "OK":
                print("> MISSING CN")
        
        # check SAN exists
        if default['id'] == 'cert_subjectAltName':
            if default['severity'] != "OK":
                print("> MISSING SAN")
        
        # check cert trust
        if default['id'] == 'cert_trust':
            if default['severity'] != "OK":
                if (default['finding'] == "certificate does not match supplied URI"):
                    pass
                else:
                    print("> CERT TRUST ISSUE")
        
        
        # check cert chain of trust
        if default['id'] == 'cert_chain_of_trust':
            if default['severity'] != "OK":
                if default['finding'] == "failed (self signed).":
                    results_self_signed.append(host)
                    print("> CERT CHAIN TRUST ISSUE (SELF SIGNED)")
        
        # check cert expiry
        if default['id'] == 'cert_chain_of_trust':
            if default['severity'] == "HIGH":
                results_expired.append(host)
                print("> CERT EXPIRED")
        
        # check cert lifespan
        if default['id'] == 'cert_notBefore':
            cert_valid_start = int(datetime.strptime(default['finding'], "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc).timestamp())
        if default['id'] == 'cert_notAfter':
            cert_valid_end = int(datetime.strptime(default['finding'], "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc).timestamp())
            if cert_valid_end - cert_valid_start > 360000:
                results_excessive_validity.append(host)
                print(f"> CERT LIFESPAN TOO LONG ({int((cert_valid_end - cert_valid_start) / 2629746)} months)")

        # check KU, EKU is appropriate

def test_ciphers(ciphers_list, host):
    global VULNERABLE_CIPHERS
    vulnerable_offered = []
    for cipher in ciphers_list:
        if cipher['finding'] == "offered" and cipher['id'] in VULNERABLE_CIPHERS:
            vulnerable_offered.append(cipher['id'])
    if len(vulnerable_offered) > 0:
        results_weak_ciphers.append(host)
        print("> Vulnerable Protocols are Offered", vulnerable_offered)

def test_forward_secrecy(fs_list, host):
    for fs in fs_list:
        if fs['id'] == "FS_TLS12_sig_algs" and "RSA+SHA1" in fs["finding"]:
            results_fs_weak.append(host)
            print("> SHA1 Forward Secrecy Offered")

def test_protocols(protocols_list, host):
    global VULNERBLE_PROTOCOLS
    vulnerable_offered = []
    for protocol in protocols_list:
        if protocol['finding'] == "offered" and protocol['id'] in VULNERBLE_PROTOCOLS:
            vulnerable_offered.append(protocol['id'])
    if len(vulnerable_offered) > 0:
        results_deprecated_protocols.append(host)
        print("> Vulnerable Protocols are Offered", vulnerable_offered)

def main():
    parser = argparse.ArgumentParser(
                        prog='TestSSLFormatter',
                        description='Digests testSSL pretty json into nice table for reports',
                        )
    parser.add_argument('filename')
    args = parser.parse_args()
    f = open(args.filename, 'r')
    # parse the json
    jsondata = json.loads(f.read())
    #print(jsondata)
    for i in jsondata['scanResult']:
        if 'ip' in list(i.keys()):
            host = f"{i['ip']}:{i['port']}"
            print("HOST: ", host)
            test_protocols(i['protocols'], host)
            test_ciphers(i['ciphers'], host)
            test_server_defaults(i['serverDefaults'], host)
            test_forward_secrecy(i['fs'], host)
    print("\n\n\n\n\n\n\n")
    if (len(results_self_signed) > 0):
        print("SELF SIGNED:")
        for i in results_self_signed:
            print(f"- {i}")
    if (len(results_expired) > 0):
        print("EXPIRED:")
        for i in results_expired:
            print(f"- {i}")
    if (len(results_excessive_validity) > 0):
        print("EXCESSIVE VALIDITY:")
        for i in results_excessive_validity:
            print(f"- {i}")
    if (len(results_signature_verification_failure) > 0):
        print("Signature Verification Failure:")
        for i in results_signature_verification_failure:
            print(f"- {i}")
    if (len(results_improper_key_usage) > 0):
        print("Signature Verification Failure:")
        for i in results_improper_key_usage:
            print(f"- {i}")
    if (len(results_deprecated_protocols) > 0):
        print("Deprecated Protocols:")
        for i in results_deprecated_protocols:
            print(f"- {i}")
    if (len(results_weak_ciphers) > 0):
        print("Weak Ciphers:")
        for i in results_weak_ciphers:
            print(f"- {i}")
    if (len(results_fs_weak) > 0):
        print("Insecure Forward Secrecy:")
        for i in results_fs_weak:
            print(f"- {i}")
    
if __name__ == "__main__":
    main()
