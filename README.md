# PasswordAtTheDisco
**Version: 0.1**

**PasswordAtTheDisco** is a powerful password auditing tool designed to evaluate and enhance password security across multiple domains. It processes both cracked and uncracked password files, integrates with BloodHound for privilege escalation analysis, and generates detailed reports to assist security teams in identifying risks and prioritizing remediation efforts. The primary goal is to improve an organization's security posture by uncovering weak passwords, shared credentials, and accounts with excessive privileges, while providing clear, actionable steps to address these issues.

## Features

- Analyzes password complexity and compliance with organizational security policies
- Integrates with BloodHound to pinpoint accounts with Domain Admin (DA) pathways and high controllables
- Identifies shared passwords and hashes across domains, highlighting potential lateral movement risks
- Generates actionable reports with prioritized remediation steps
- Creates visualizations (graphs and charts) for an intuitive understanding of password security metrics
- Supports multi-domain environments for comprehensive analysis

## Installation

To set up **PasswordAtTheDisco**, follow these steps:

1. Clone the repository from GitHub:

```
git clone https://github.com/watson0x90/PasswordAtTheDisco.git
```

3. Install the required Python dependencies:
```
pip install -r requirements
```

4. Ensure BloodHound is installed and configured correctly for privilege analysis integration. You will also need to generate an API token for the BloodHound API.
    - https://bloodhound.specterops.io/integrations/bloodhound-api/working-with-api#create-a-personal-api-key-and-id-pair

**Note:** It is assumed that you have collected the domain information using SharpHound. This project is not designed to collect SharpHound data for you. 
  
5. Update the `core\bloodhound_client.py` with your information. Example:

```
BHE_DOMAIN = "10.0.0.21"
BHE_PORT = 8080
BHE_SCHEME = "http"
BHE_TOKEN_ID = "YOUR_TOKEN_ID_HERE"
BHE_TOKEN_KEY = "YOUR_TOKEN_KEY_HERE"
```

## Expected Data
As of right now, it is assumed that you have already worked on cracking passwords using Hashcat. Your `username_and_hash_file.txt` MUST be in the following format:

```
user@DOMAIN1.INT:35301:aad3b435b51404eeaad3b435b51404ee:8846F7EAEE8FB117AD06BDD830B7586C:::
```

We utilize the first part `user@DOMAIN1.int` to look up accounts in BloodHound. If you have two accounts across domains with the same name, it will pull the first object it finds, giving you invalid results. And nobody wants that!

To generate the cracked file, run the following command, obviously replacing the necessary items with the correct values:

```
hashcat -m 1000 --show --username --potfile-path domain1_audit_2024.pot username_and_hash_file.txt > domain1_cracked.txt
```

To generate the uncracked file, change the necessary file names as before in the command below:
```
hashcat -m 1000 --left --username --potfile-path domain1_audit_2024.pot username_and_hash_file.txt > domain1_cracked.txt
```
If you have more domains to audit in the same Forest, generate more cracked and uncracked files. But don't worry, we are capable of auditing a single domain. :)
 
## Usage

**PasswordAtTheDisco** is a command-line tool with several options to customize its behavior:

- `-d, --domains`: Specify domains and their associated cracked and uncracked password files in the format `domain:cracked_file:uncracked_file`. You can provide multiple domains.
- `-p, --pdf`: Generate PDF versions of existing Markdown reports without reprocessing data.
- `-s, --serve`: Serve the HTML reports folder via a local HTTP server for easy access.
- `-v, --version`: Display the current version of the tool.

### Command-Line Examples

1. **Analyze a single domain**:

```
python audit.py -d "DOMAIN1.INT:domain1_cracked.txt:domain1_uncracked.txt"
```

This processes password files for DOMAIN1.INT and generates reports.

2. **Analyze multiple domains**:
```
python audit.py -d "DOMAIN1.INT:domain1_cracked.txt:domain1_uncracked.txt" "DOMAIN2.COM:domain2_cracked.txt:domain2_uncracked.txt"
```

This analyzes password security across DOMAIN1.INT and DOMAIN2.COM, including cross-domain password sharing.

3. **Generate PDFs from existing reports**:

```
python audit.py --pdf
```

Converts existing Markdown reports to PDF format without re-running the analysis.

4. **Serve HTML reports locally**:

```
python audit.py -s
```
Starts a local HTTP server to view HTML reports in a browser.

## Reports

**PasswordAtTheDisco** produces a variety of reports to help security teams understand and act on password-related findings:

- **Single Domain Reports**: In-depth analysis of password security for each domain, covering complexity, policy compliance, and risk levels.
- **Combined Cross-Domain Report**: Examines password and hash sharing across domains, identifying credentials that could enable lateral movement.
- **Actionable Reports**: Lists high-priority accounts (e.g., those with DA pathways or non-expiring passwords) with remediation recommendations.
- **Explained Actionable Report**: A detailed guide explaining each section of the actionable report, its significance, and remediation steps.
- **Visualizations**: Graphs and charts visualizing metrics like risk distribution and password complexity.

Reports are output in Markdown, HTML, and CSV formats, with PDFs generated for Markdown files.

## Contributing

We welcome contributions to **PasswordAtTheDisco**! To contribute:

1. Fork the repository on GitHub.
2. Create a new branch for your feature or bug fix.
3. Commit your changes with clear, descriptive messages.
4. Push your branch to your forked repository.
5. Submit a pull request to the main repository for review.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
