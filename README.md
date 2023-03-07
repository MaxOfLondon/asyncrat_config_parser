# AsyncRATConfigParser 
![License:MIT](https://badgen.net/badge/License/MIT) ![Langugage:Python 3.8+](https://badgen.net/badge/Language/Python%203.8+/green) ![warning:malware-related](https://badgen.net/badge/Warning/malware-related/orange) ![Tested-on:Linux](https://badgen.net/badge/Tested-on/Linux)

AsyncRATConfigParser is the pure python3 class that parses configuration out of AsyncRAT Windows .NET executable malware.
Parser returns JSON formatted configuration from the client with option to parse server certificate in OpenSSL style.

Credit for the approach and majority of code goes to jeFF0Falltrades who published exceptionally instructional tutorial on YouTube titled "Baby’s First Malware Config Parser: Mini-Course w/ dnSpy+CyberChef+Python".

## Installation
```bash
$ git clone https://github.com/MaxOfLondon/asyncrat_cnf_parser.git
$ cd asyncrat_cnf_parser
$ python -m pip install -r requirements.txt
```
This repository includes sample of client malware in password protected 7z format.

> :warning: **WARNING**: Use only on isolated vm instance at own risk. I will not be held accountable for damages caused by inproper handling of the malware sample. 

Password to extract sample is: infected.
```bash
$ 7z x client.7z -Pinfected
```

## Usage
For arguments help:
```bash
$ ./asyncratparser.py -h
usage: asyncratparser.py [-h] [-c] [-d] filepath [filepath ...]

Parses configuration of AsyncRAT malware client as JSON.

positional arguments:
  filepath          one or more AsyncRAT payload filepaths

optional arguments:
  -h, --help        show this help message and exit
  -c, --parse-cert  return parsed certificate instead of base64 string
  -d, --debug       enable debug logging
```
Example output:
```bash
$ ./asyncratparser.py client.exe | python -m json.tool
{
    "AES key": "df7e566dd10cb747b9410619ed60f9c41beb9e26daab0d13949554eea2e265dc",
    "AES salt": "bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941",
    "config": {
        "Anti": "false",
        "BDOS": "false",
        "Certificate": "MIIE8jCCAtqgAwIBAgIQAK+lbA+nHCrUe5CPbqIwjTANBgkqhkiG9w0BAQ0FADAaMRgwFgYDVQQDDA9Bc3luY1JBVCBTZXJ2ZXIwIBcNMjMwMTAxMTM1MzIzWhgPOTk5OTEyMzEyMzU5NTlaMBoxGDAWBgNVBAMMD0FzeW5jUkFUIFNlcnZlcjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIPJeb9q4LjUFsTXDcbaywf7LmPmJpxmL8ZdrdK76JCUJmj7xmheH0pAVribi0uOEAZrZ2i1fyyYNBrbn1oHmLfjZLpqo4qWuve2OAFy5O6HkB9REoGg5o50bneFeXUAul6LvOLBFy+723Db/N8QwI2pqRKBiJjvu88B1ZACywcGsO3PaAIB8KpdZSd08PlPRRZSaFnlz8lJF9+fFXdCddiy7LUm69YGxSRkpLjF7xWMT+H+3FWhTyZxUsbGscvyBtDhsSru3YklHwJUZ1eIb3LNWrnmK1o/yYhz58DhrGP1B6lKvHDCnBpyJp0iuzgtQe39kC8qwNSAj3DTzEKb0vzMPYc59B3JxmmL9mHqnwguZzzfSHEG5z02GYAG3X4pTH65eBtA2LD9FGJVs4ugN6cjsGBYIsAKdiN0eFImT99xHPA/ilRJpVN31LDsGRBV/IBAUB7s434hmngrUi2jtwrNjBinuDGbDmCwMskxS4sp4QnTeafs125+OnAssPaxQn8Dgi57NKLHQiStEgSySHsB/n7gv9FHB8nxpXS39FpT6QFEX8f8ufeiA07ake+X65A9TPyw9FgK5vT+HNDrvxquNw28eFafTGWGiEq7u1BVSC6ZBfNR6picc6tA6fBGLuvZUy6KGOl/QxNzhDwwzKAXFMPWSxqTLSUvEOUiwBddAgMBAAGjMjAwMB0GA1UdDgQWBBS9yyX9zicB46HLkB1ZSUKyeYRK5TAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4ICAQAkN201z0JfEBw/XeVP8RGQpvdDzfjowHZF/SWQGMwX2IxVTO0lzXNRVaScvIWNBhSPN25jJw48YX02P+zzWemovMC4ifzyCPOOmVupFDx1G14WduqVVXBCtA+MOVe1qcZt7c6m08IkJbITyZ/BfufQqVwz8QCaa8Sw5hcX9ehzB8gQP6Sil3aAVVDKEIal5RAz1JKEtg2fmKS5iZSutseqRhtWm9SnL+XFXKeCH9ZnGAudCsey+Cd0yCFw1HJd6tABfFIvX6uXmUKY7NNXYzRCQ6xBMGF/KdVGkMgE29oZ/8ens1VYXZwDMl/vOCUGqBe9gswOkX01SjLVJwa2L0SPh/8xpWsSwAD4ZpGf2PF8d2AxhXufaENwwiQwE/0L4vfCLir82OBSbSaZ2ehTWcYLE0KVIEHQwQsbpETXbgVJiAvuI2jnlmz7vLTwzWrbeiczzvwHqzo1cwtCpgJbixPEK0jey+C0qHJl124fPOYFD6URk/uLy4mQB1KmyJq5nCBotmPIUv9WUi+ZjlviEnhKIg1vHgmWlmn0MXlB88qu4Lbf3GCDkaubpmiL7qHhWXPzoAaKlFRbFtj4O6VYkvy4S/bs9Z7GWapIRBEVQAmyZB8W8W1oRWpNzXefUnTyNw4Y8uN8khFEB8Dxt8fhQmd50hGPq2Nz2QTtZj18UjWUJw==",
        "Delay": "3",
        "Group": "Default",
        "Hosts": "207.244.236.205",
        "Install": "false",
        "InstallFile": "",
        "InstallFolder": "%AppData%",
        "Key": "CojRIJtp8HBog73SEs02GiO916GxQgSJ",
        "MTX": "AsyncMutex_6SI8OkPnk",
        "Pastebin": "null",
        "Ports": "6606,7707,8808",
        "Serversignature": "0x5cd90bcc768b388b6ba3d28b606485eb195d7961a743db54eb2d9854d70a96078746d781e68a380cec29ea9ea2bb3faa9906fa6c2bbf3cbb07dcadc663346c06f557b98bee1fc8a27f6a2ba1ec1a4259ec95da70a52693259d5c8cbdb4820f00f6a55b2a1c5f43b5bda5dde9658af22df76b1fc1e687754b32034f8d0763c7a85de541ff5d65689d2c7f4a620f85a64dc9d708422575859a5f8fba00abf131a8972eed33662411bd4f88d0d824fa5934a2d1037eb19d747667efbb2cab3eaa30cb7e4fc0f5b38d352a85e08c5473ae72772327715adf79fad3b02ea947edef30bf674e5e40c545558e586b96dff0475b97bdf15832149a90213cb5d7030042e8adb0b65d1cfb7813db1b0d58f00a0752253f34601181881bd15a71a164b8704bfdc9db8b973c7f818e15af58c60ddb9af7ff752c207d123abee2c4cb241dfae0abdde17649ed1d00c82e8ce1e46b0091a5b8aa11ef7bddaf6231b1898b06c1f125204c747bdec6850d6d2b5f5dda25142e06eb6955a9415e03ea64b2f1c15864aef600d4050b5e88268e96bd086f30612b9efc571849787c317bc82a8a16014d3f5b19565da1a3b709792f3e08a47cde988d2b0de803e1848be2a61e9a395e1284c4f8474ff2201a27126a292c7e17f4ff0345b4cd8ad784fd0fee9a626a94edfcdbc68cc4f316acb2fce065e39517c7a4462df73c75ed241f5c06ad1ffac741",
        "Version": "0.5.7B"
    },
    "filepath": "client.exe"
}
```

Example output with parsed certificate:
```bash
$ ./asyncratparser.py --parse-cert client.exe | python -m json.tool
{
    "AES key": "df7e566dd10cb747b9410619ed60f9c41beb9e26daab0d13949554eea2e265dc",
    "AES salt": "bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941",
    "config": {
        "Anti": "false",
        "BDOS": "false",
        "Certificate": {
            "issued_by": "CN=AsyncRAT Server",
            "public_bytes": "-----BEGIN CERTIFICATE-----\nMIIE8jCCAtqgAwIBAgIQAK+lbA+nHCrUe5CPbqIwjTANBgkqhkiG9w0BAQ0FADAa\nMRgwFgYDVQQDDA9Bc3luY1JBVCBTZXJ2ZXIwIBcNMjMwMTAxMTM1MzIzWhgPOTk5\nOTEyMzEyMzU5NTlaMBoxGDAWBgNVBAMMD0FzeW5jUkFUIFNlcnZlcjCCAiIwDQYJ\nKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIPJeb9q4LjUFsTXDcbaywf7LmPmJpxm\nL8ZdrdK76JCUJmj7xmheH0pAVribi0uOEAZrZ2i1fyyYNBrbn1oHmLfjZLpqo4qW\nuve2OAFy5O6HkB9REoGg5o50bneFeXUAul6LvOLBFy+723Db/N8QwI2pqRKBiJjv\nu88B1ZACywcGsO3PaAIB8KpdZSd08PlPRRZSaFnlz8lJF9+fFXdCddiy7LUm69YG\nxSRkpLjF7xWMT+H+3FWhTyZxUsbGscvyBtDhsSru3YklHwJUZ1eIb3LNWrnmK1o/\nyYhz58DhrGP1B6lKvHDCnBpyJp0iuzgtQe39kC8qwNSAj3DTzEKb0vzMPYc59B3J\nxmmL9mHqnwguZzzfSHEG5z02GYAG3X4pTH65eBtA2LD9FGJVs4ugN6cjsGBYIsAK\ndiN0eFImT99xHPA/ilRJpVN31LDsGRBV/IBAUB7s434hmngrUi2jtwrNjBinuDGb\nDmCwMskxS4sp4QnTeafs125+OnAssPaxQn8Dgi57NKLHQiStEgSySHsB/n7gv9FH\nB8nxpXS39FpT6QFEX8f8ufeiA07ake+X65A9TPyw9FgK5vT+HNDrvxquNw28eFaf\nTGWGiEq7u1BVSC6ZBfNR6picc6tA6fBGLuvZUy6KGOl/QxNzhDwwzKAXFMPWSxqT\nLSUvEOUiwBddAgMBAAGjMjAwMB0GA1UdDgQWBBS9yyX9zicB46HLkB1ZSUKyeYRK\n5TAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4ICAQAkN201z0JfEBw/\nXeVP8RGQpvdDzfjowHZF/SWQGMwX2IxVTO0lzXNRVaScvIWNBhSPN25jJw48YX02\nP+zzWemovMC4ifzyCPOOmVupFDx1G14WduqVVXBCtA+MOVe1qcZt7c6m08IkJbIT\nyZ/BfufQqVwz8QCaa8Sw5hcX9ehzB8gQP6Sil3aAVVDKEIal5RAz1JKEtg2fmKS5\niZSutseqRhtWm9SnL+XFXKeCH9ZnGAudCsey+Cd0yCFw1HJd6tABfFIvX6uXmUKY\n7NNXYzRCQ6xBMGF/KdVGkMgE29oZ/8ens1VYXZwDMl/vOCUGqBe9gswOkX01SjLV\nJwa2L0SPh/8xpWsSwAD4ZpGf2PF8d2AxhXufaENwwiQwE/0L4vfCLir82OBSbSaZ\n2ehTWcYLE0KVIEHQwQsbpETXbgVJiAvuI2jnlmz7vLTwzWrbeiczzvwHqzo1cwtC\npgJbixPEK0jey+C0qHJl124fPOYFD6URk/uLy4mQB1KmyJq5nCBotmPIUv9WUi+Z\njlviEnhKIg1vHgmWlmn0MXlB88qu4Lbf3GCDkaubpmiL7qHhWXPzoAaKlFRbFtj4\nO6VYkvy4S/bs9Z7GWapIRBEVQAmyZB8W8W1oRWpNzXefUnTyNw4Y8uN8khFEB8Dx\nt8fhQmd50hGPq2Nz2QTtZj18UjWUJw==\n-----END CERTIFICATE-----\n",
            "public_key": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAg8l5v2rguNQWxNcNxtrL\nB/suY+YmnGYvxl2t0rvokJQmaPvGaF4fSkBWuJuLS44QBmtnaLV/LJg0GtufWgeY\nt+Nkumqjipa697Y4AXLk7oeQH1ESgaDmjnRud4V5dQC6Xou84sEXL7vbcNv83xDA\njampEoGImO+7zwHVkALLBwaw7c9oAgHwql1lJ3Tw+U9FFlJoWeXPyUkX358Vd0J1\n2LLstSbr1gbFJGSkuMXvFYxP4f7cVaFPJnFSxsaxy/IG0OGxKu7diSUfAlRnV4hv\ncs1aueYrWj/JiHPnwOGsY/UHqUq8cMKcGnImnSK7OC1B7f2QLyrA1ICPcNPMQpvS\n/Mw9hzn0HcnGaYv2YeqfCC5nPN9IcQbnPTYZgAbdfilMfrl4G0DYsP0UYlWzi6A3\npyOwYFgiwAp2I3R4UiZP33Ec8D+KVEmlU3fUsOwZEFX8gEBQHuzjfiGaeCtSLaO3\nCs2MGKe4MZsOYLAyyTFLiynhCdN5p+zXbn46cCyw9rFCfwOCLns0osdCJK0SBLJI\newH+fuC/0UcHyfGldLf0WlPpAURfx/y596IDTtqR75frkD1M/LD0WArm9P4c0Ou/\nGq43Dbx4Vp9MZYaISru7UFVILpkF81HqmJxzq0Dp8EYu69lTLooY6X9DE3OEPDDM\noBcUw9ZLGpMtJS8Q5SLAF10CAwEAAQ==\n-----END PUBLIC KEY-----\n",
            "serial_number": "af:a5:6c:0f:a7:1c:2a:d4:7b:90:8f:6e:a2:30:8d",
            "signature": "27:94:35:52:7c:3d:66:ed:04:d9:73:63:ab:8f:11:d2:79:67:42:e1:c7:b7:f1:c0:07:44:11:92:7c:e3:f2:18:0e:37:f2:74:52:9f:77:cd:4d:6a:45:68:6d:f1:16:1f:64:b2:09:40:15:11:44:48:aa:59:c6:9e:f5:ec:f6:4b:b8:fc:92:58:a5:3b:f8:d8:16:5b:54:94:8a:06:a0:f3:73:59:e1:a1:ee:8b:68:a6:9b:ab:91:83:60:dc:df:b6:e0:ae:ca:f3:41:79:31:f4:69:96:96:09:1e:6f:0d:22:4a:78:12:e2:5b:8e:99:2f:52:56:ff:52:c8:63:b6:68:20:9c:b9:9a:c8:a6:52:07:90:89:cb:8b:fb:93:11:a5:0f:05:e6:3c:1f:6e:d7:65:72:a8:b4:e0:cb:de:48:2b:c4:13:8b:5b:02:a6:42:0b:73:35:3a:ab:07:fc:ce:33:27:7a:db:6a:cd:f0:b4:bc:fb:6c:96:e7:68:23:ee:0b:88:49:05:6e:d7:44:a4:1b:0b:c1:d0:41:20:95:42:13:0b:c6:59:53:e8:d9:99:26:6d:52:e0:d8:fc:2a:2e:c2:f7:e2:0b:fd:13:30:24:c2:70:43:68:9f:7b:85:31:60:77:7c:f1:d8:9f:91:66:f8:00:c0:12:6b:a5:31:ff:87:8f:44:2f:b6:06:27:d5:32:4a:35:7d:91:0e:cc:82:bd:17:a8:06:25:38:ef:5f:32:03:9c:5d:58:55:b3:a7:c7:ff:19:da:db:04:c8:90:46:d5:29:7f:61:30:41:ac:43:42:34:63:57:d3:ec:98:42:99:97:ab:5f:2f:52:7c:01:d0:ea:5d:72:d4:70:21:c8:74:27:f8:b2:c7:0a:9d:0b:18:67:d6:1f:82:a7:5c:c5:e5:2f:a7:d4:9b:56:1b:46:aa:c7:b6:ae:94:89:b9:a4:98:9f:0d:b6:84:92:d4:33:10:e5:a5:86:10:ca:50:55:80:76:97:a2:a4:3f:10:c8:07:73:e8:f5:17:17:e6:b0:c4:6b:9a:00:f1:33:5c:a9:d0:e7:7e:c1:9f:c9:13:b2:25:24:c2:d3:a6:ce:ed:6d:c6:a9:b5:57:39:8c:0f:b4:42:70:55:95:ea:76:16:5e:1b:75:3c:14:a9:5b:99:8e:f3:08:f2:fc:89:b8:c0:bc:a8:e9:59:f3:ec:3f:36:7d:61:3c:0e:27:63:6e:37:8f:14:06:8d:85:bc:9c:a4:55:51:73:cd:25:ed:4c:55:8c:d8:17:cc:18:90:25:fd:45:76:c0:e8:f8:cd:43:f7:a6:90:11:f1:4f:e5:5d:3f:1c:10:5f:42:cf:35:6d:37:24",
            "signature_algorithm": "sha512WithRSAEncryption",
            "signature_hash_algorithm": "sha512",
            "subject": "CN=AsyncRAT Server",
            "subject_public_key_info": {
                "exponent": "65537 (0x10001)",
                "modulus": "83:c9:79:bf:6a:e0:b8:d4:16:c4:d7:0d:c6:da:cb:07:fb:2e:63:e6:26:9c:66:2f:c6:5d:ad:d2:bb:e8:90:94:26:68:fb:c6:68:5e:1f:4a:40:56:b8:9b:8b:4b:8e:10:06:6b:67:68:b5:7f:2c:98:34:1a:db:9f:5a:07:98:b7:e3:64:ba:6a:a3:8a:96:ba:f7:b6:38:01:72:e4:ee:87:90:1f:51:12:81:a0:e6:8e:74:6e:77:85:79:75:00:ba:5e:8b:bc:e2:c1:17:2f:bb:db:70:db:fc:df:10:c0:8d:a9:a9:12:81:88:98:ef:bb:cf:01:d5:90:02:cb:07:06:b0:ed:cf:68:02:01:f0:aa:5d:65:27:74:f0:f9:4f:45:16:52:68:59:e5:cf:c9:49:17:df:9f:15:77:42:75:d8:b2:ec:b5:26:eb:d6:06:c5:24:64:a4:b8:c5:ef:15:8c:4f:e1:fe:dc:55:a1:4f:26:71:52:c6:c6:b1:cb:f2:06:d0:e1:b1:2a:ee:dd:89:25:1f:02:54:67:57:88:6f:72:cd:5a:b9:e6:2b:5a:3f:c9:88:73:e7:c0:e1:ac:63:f5:07:a9:4a:bc:70:c2:9c:1a:72:26:9d:22:bb:38:2d:41:ed:fd:90:2f:2a:c0:d4:80:8f:70:d3:cc:42:9b:d2:fc:cc:3d:87:39:f4:1d:c9:c6:69:8b:f6:61:ea:9f:08:2e:67:3c:df:48:71:06:e7:3d:36:19:80:06:dd:7e:29:4c:7e:b9:78:1b:40:d8:b0:fd:14:62:55:b3:8b:a0:37:a7:23:b0:60:58:22:c0:0a:76:23:74:78:52:26:4f:df:71:1c:f0:3f:8a:54:49:a5:53:77:d4:b0:ec:19:10:55:fc:80:40:50:1e:ec:e3:7e:21:9a:78:2b:52:2d:a3:b7:0a:cd:8c:18:a7:b8:31:9b:0e:60:b0:32:c9:31:4b:8b:29:e1:09:d3:79:a7:ec:d7:6e:7e:3a:70:2c:b0:f6:b1:42:7f:03:82:2e:7b:34:a2:c7:42:24:ad:12:04:b2:48:7b:01:fe:7e:e0:bf:d1:47:07:c9:f1:a5:74:b7:f4:5a:53:e9:01:44:5f:c7:fc:b9:f7:a2:03:4e:da:91:ef:97:eb:90:3d:4c:fc:b0:f4:58:0a:e6:f4:fe:1c:d0:eb:bf:1a:ae:37:0d:bc:78:56:9f:4c:65:86:88:4a:bb:bb:50:55:48:2e:99:05:f3:51:ea:98:9c:73:ab:40:e9:f0:46:2e:eb:d9:53:2e:8a:18:e9:7f:43:13:73:84:3c:30:cc:a0:17:14:c3:d6:4b:1a:93:2d:25:2f:10:e5:22:c0:17:5d",
                "public_key_algorithm": "rsaEncryption",
                "rsa_public_key_length": 4096
            },
            "validity": {
                "not_valid_after": "9999-12-31 23:59:59",
                "not_valid_before": "2023-01-01 13:53:23"
            },
            "version": "3 (0x2)",
            "x509v3_extensions": [
                {
                    "subject_key_identifier": "e5:4a:84:79:b2:42:49:59:1d:90:cb:a1:e3:01:27:ce:fd:25:cb:bd"
                },
                {
                    "basic_constraints": {
                        "ca": true,
                        "critical": true
                    }
                }
            ]
        },
        "Delay": "3",
        "Group": "Default",
        "Hosts": "207.244.236.205",
        "Install": "false",
        "InstallFile": "",
        "InstallFolder": "%AppData%",
        "Key": "CojRIJtp8HBog73SEs02GiO916GxQgSJ",
        "MTX": "AsyncMutex_6SI8OkPnk",
        "Pastebin": "null",
        "Ports": "6606,7707,8808",
        "Serversignature": "0x5cd90bcc768b388b6ba3d28b606485eb195d7961a743db54eb2d9854d70a96078746d781e68a380cec29ea9ea2bb3faa9906fa6c2bbf3cbb07dcadc663346c06f557b98bee1fc8a27f6a2ba1ec1a4259ec95da70a52693259d5c8cbdb4820f00f6a55b2a1c5f43b5bda5dde9658af22df76b1fc1e687754b32034f8d0763c7a85de541ff5d65689d2c7f4a620f85a64dc9d708422575859a5f8fba00abf131a8972eed33662411bd4f88d0d824fa5934a2d1037eb19d747667efbb2cab3eaa30cb7e4fc0f5b38d352a85e08c5473ae72772327715adf79fad3b02ea947edef30bf674e5e40c545558e586b96dff0475b97bdf15832149a90213cb5d7030042e8adb0b65d1cfb7813db1b0d58f00a0752253f34601181881bd15a71a164b8704bfdc9db8b973c7f818e15af58c60ddb9af7ff752c207d123abee2c4cb241dfae0abdde17649ed1d00c82e8ce1e46b0091a5b8aa11ef7bddaf6231b1898b06c1f125204c747bdec6850d6d2b5f5dda25142e06eb6955a9415e03ea64b2f1c15864aef600d4050b5e88268e96bd086f30612b9efc571849787c317bc82a8a16014d3f5b19565da1a3b709792f3e08a47cde988d2b0de803e1848be2a61e9a395e1284c4f8474ff2201a27126a292c7e17f4ff0345b4cd8ad784fd0fee9a626a94edfcdbc68cc4f316acb2fce065e39517c7a4462df73c75ed241f5c06ad1ffac741",
        "Version": "0.5.7B"
    },
    "filepath": "client.exe"
}
```

AsyncRATConfigParser was tested on Ubuntu 20LTS, python 3.8 with cryptography 23.0.0.
