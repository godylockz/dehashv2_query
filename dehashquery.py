#!/usr/bin/env python3
"""This script calls the dehashed API v2 to parse emails, passwords, and password hashes.
Reference: https://app.dehashed.com/documentation/api
"""

# Imports
from dataclasses import dataclass
from itertools import product
from typing import List, Dict, Any
import argparse
import csv
import json
import os
import requests
import sys


# ANSI color codes
class Colors:
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    NOCOLOR = "\033[0m"


@dataclass
class Config:
    domain: str
    api_key: str
    base_url: str = "https://api.dehashed.com/v2/search"
    output_dir: str = ""

    def __post_init__(self):
        self.output_dir = self.domain
        self._setup_directory()

    def _setup_directory(self) -> None:
        """Create output directory if it doesn't exist."""
        if not os.path.exists(self.output_dir):
            print(f"{Colors.CYAN}Creating save directory: {self.output_dir}{Colors.NOCOLOR}")
            os.makedirs(self.output_dir)
        print(f"{Colors.CYAN}[*] Save Directory: {self.output_dir}{Colors.NOCOLOR}")
        os.chdir(self.output_dir)


class DehashedProcessor:
    def __init__(self, config: Config):
        self.config = config
        self.data_file = "allData.json"
        self.headers = {"Content-Type": "application/json", "Dehashed-Api-Key": config.api_key, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    def fetch_data(self) -> Dict[str, Any]:
        """Fetch data from Dehashed API if not already cached."""
        if not os.path.isfile(self.data_file):
            while True:
                response = input("Cannot find previously downloaded data, fetch new API query and consume token (y/n): ").strip().lower()
                if response in ["y", "yes"]:
                    break
                elif response in ["n", "no"]:
                    exit()
                else:
                    print("Please enter 'y' or 'n'.")
            print(f"{Colors.CYAN}[*] Downloading data, domain: {self.config.domain} ...{Colors.NOCOLOR}")
            payload = {"query": f'domain:{self.config.domain}', "page": 1, "size": 10000, "regex": False, "wildcard": False, "de_dupe": False}
            response = requests.post(self.config.base_url, headers=self.headers, json=payload)
            if response.status_code != 200:
                print(response.text)
                raise ValueError("[-] Invalid query")

            data = response.json()
            with open(self.data_file, "w") as f:
                json.dump(data, f, indent=4)
            print(f"{Colors.CYAN}[*] Data saved to {self.data_file} for domain: {self.config.domain}{Colors.NOCOLOR}")
            return data
        else:
            print(f"{Colors.CYAN}[*] Data read from {self.data_file} for domain: {self.config.domain}{Colors.NOCOLOR}")
            with open(self.data_file, "r") as f:
                return json.load(f)

    @staticmethod
    def normalize_field(value: Any, field_name: str) -> List[str]:
        """Normalize and filter field values."""
        values = value if isinstance(value, list) else [value]
        result = []
        for v in values:
            if v is not None and v != "":
                if field_name == "name":
                    if "@" in v:
                        # Skip if it's an email
                        continue
                    # Capitalize first letter of each word, lowercase the rest
                    v = " ".join(word.capitalize() for word in v.split())
                elif field_name == "email":
                    v = v.lower()
                elif field_name == "hashed_password":
                    if ":None||" in v:
                        continue
                    if ":||" in v:
                        v = v.split(":||")[0]
                v = v.strip()
                result.append(v)
        return result

    def process_entries(self, entries: List[Dict]) -> None:
        """Process entries and generate output files."""
        self.write_emails(entries)
        self.write_email_passwords(entries)
        self.write_email_hashes(entries)
        self.write_csv(entries)

    def write_emails(self, entries: List[Dict]) -> None:
        """Get email combinations."""
        rows = []
        for entry in entries:
            emails = self.normalize_field(entry.get("email", ""), "email")
            if emails:
                rows.extend(f"{e}" for e in emails)
        self._write_file("emails.txt", sorted(set(rows)))

    def write_email_passwords(self, entries: List[Dict]) -> None:
        """Generate email:password combinations."""
        rows = []
        for entry in entries:
            emails = self.normalize_field(entry.get("email", ""), "email")
            passwords = self.normalize_field(entry.get("password", ""), "password")
            if emails and passwords:
                rows.extend(f"{e}:{p}" for e, p in product(emails, passwords))

        self._write_file("emailAndPassword.txt", sorted(set(rows)))

    def write_email_hashes(self, entries: List[Dict]) -> None:
        """Generate email:hash combinations."""
        rows = []
        for entry in entries:
            emails = self.normalize_field(entry.get("email", ""), "email")
            hashes = self.normalize_field(entry.get("hashed_password", ""), "hashed_password")
            if emails and hashes:
                rows.extend(f"{e}:{h}" for e, h in product(emails, hashes))

        self._write_file("emailAndHash.txt", sorted(set(rows)))

    def write_csv(self, entries: List[Dict]) -> None:
        """Generate CSV with all field combinations."""
        fields = ["email", "ip_address", "username", "password", "hashed_password", "name", "vin", "address", "phone", "database_name"]
        header = ["Email", "IP Address", "Username", "Password", "Hash", "Name", "VIN", "Address", "Phone", "Database"]

        rows = []
        for entry in entries:
            normalized = {f: self.normalize_field(entry.get(f, ""), f) or [""] for f in fields}
            rows.extend(product(*[normalized[f] for f in fields]))

        with open("outData.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(sorted(set(rows)))
        print(f"{Colors.GREEN}[*] outData.csv created, {len(rows) + 1} entries.{Colors.NOCOLOR}")

    def _write_file(self, filename: str, rows: List[str]) -> None:
        """Write rows to file and print status."""
        with open(filename, "w") as f:
            f.write("\n".join(rows) + "\n")
        print(f"{Colors.GREEN}[*] {filename} created, {len(rows)} entries.{Colors.NOCOLOR}")


def main():
    parser = argparse.ArgumentParser(description="Process domain data from Dehashed API")
    parser.add_argument("-d", "--domain", required=True, help="Domain name to query")
    parser.add_argument("-k", "--apikey", required=True, help="Dehashed API key")
    args = parser.parse_args()

    try:
        config = Config(domain=args.domain, api_key=args.apikey)
        processor = DehashedProcessor(config)
        data = processor.fetch_data()
        entries = data.get("entries", data) if isinstance(data, dict) else data
        processor.process_entries(entries)
        print(f"{Colors.GREEN}[*] Done{Colors.NOCOLOR}")
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
