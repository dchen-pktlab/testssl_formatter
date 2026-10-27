# TestSSL Version:
3.2.4

# TestSSL Process
testssl -e -s -p -S --connect-timeout 5 --openssl-timeout 5 --file scope_ips.txt --jsonfile test_ssl_out.json

# TODO:
- [ ] results_signature_verification_failure
- [ ] results_improper_key_usage
- [ ] hostname mismatch
- [ ] insecure signatuere algorithm (SHA1)

# Usage
```
python testssl_script.py temp.json
```

