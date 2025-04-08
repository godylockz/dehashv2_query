# Dehash API V2 Query Script

This script utilizes the Dehashed API v2 to retrieve and parse emails, passwords, and password hashes associated with a specified domain.

**Note:** The legacy API (v1) is deprecated and no longer functional. You may need to regenerate your API key to align with the updated v2 syntax. Refer to the official documentation for details: <https://app.dehashed.com/documentation/api>

## Output Files

- `emails.txt`: List of retrieved email addresses.
- `emailAndPassword.txt`: Email and plaintext password pairs.
- `emailAndHash.txt`: Email and password hash pairs.
- `outData.csv`: Comprehensive output in CSV format.

## Usage Example

```text
usage: dehashQuery.py [-h] -d DOMAIN -k APIKEY

Process domain data from Dehashed API

options:
  -h, --help           Show this help message and exit
  -d, --domain DOMAIN  Domain name to query (e.g., example.com)
  -k, --apikey APIKEY  Dehashed API key
```

Run the script from the command line with your API key and target domain:

```sh
$ python3 dehashQuery.py -k '<api_key>' -d '<domain>'
[*] Save Directory: <domain>
[*] emails.txt created, 5 entries.
[*] emailAndPassword.txt created, 3 entries.
[*] emailAndHash.txt created, 10 entries.
[*] outData.csv created, 10 entries.
[*] Done
```
