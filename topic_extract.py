#!/usr/bin/env/python

import json
import os
import click
import uuid
import datetime
from openai import OpenAI
from typing import Dict, List
from pprint import pprint

MODEL = "o3-mini"
VERSION = "0.1.0"


def extract_topics_from_text(text: str, model: str = MODEL) -> Dict:
    """
    Extract all relevant infos fro the text and stuff it into a MISP taxonomy JSON object
    which is defined here https://www.misp-project.org/objects.html#_summariser_output

    :param text: The text to be processed
    :param model: The model to be used for processing, defaults to MODEL

    Returns:
        A dictionary containing the extracted topics.
        Example:
        {
            "title": "Russian APT29 hackers' stealthy malware undetected for years",   # Title of the original text
            "summary":  "the quick brown fox alwyas jumps",         # a short summary of the text
            "description": "automatic AI processing of the text",   # some description
            "original-text": text,                                  # "Original text before any processing."
            # Publication date of the original text (not related to the processing)
            "original-text-timestamp": "2023-10-01T00:00:00Z",
            "original-url": "https://example.com",                  # URL of the original text
            "summariser-model": "o3-mini",                          # Model used for processing
            "summariser-timestamp": "2023-10-01T00:00:00Z",         # Timestamp of the processing
            "summariser-version": "0.1.0",                          # Version of the code used for the summariser.
            "tcode": "T1001.01",                                    # A MITRE ATT&CK T-Code
            "tcode": T1087.004",                                    # Another MITRE ATT&CK T-Code
            "tcode": "T1548.006",                                   # And another MITRE ATT&CK T-Code
              # TTP of the original text extracted by the AI-based or NLP-based summariser.
            "ttp": "Account Manipulation",
              # Another TTP of the original text extracted by the AI-based or NLP-based summariser.
            "ttp": "Credential Dumping",
            "uuid": "38633d19-123a-4b0f-bc4a-ccb381e58e49",          # UUID of the object
            "version": 1
        }
    """

    try:
        # Initialize OpenAI API client
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    except Exception as e:
        print(f"Error initializing OpenAI API client: {e}")
        raise e

    # Define the prompt for the model
    PROMPT = """You are a cyber Threat Intelligence (CTI) Analyst and are tasked to summarize the following CTI report.
    You will extract the relevant information and stuff it into a MISP taxonomy JSON object which is defined here https://www.misp-project.org/objects.html#_summariser_output
    Here is an example JSON output. Adjust the values according to the CTI report you are processing. The tcodes are just examples 
    and should be replaced with the ones you find in the CTI report. Try hard to extract the tcodes and ttps from the text:

    {
            "title": "Russian APT29 hackers' stealthy malware undetected for years",   # Title of the original text
            "summary":  "the quick brown fox alwyas jumps",         # a short summary of the text
            "description": "automatic AI processing of the text",   # some description
            "original-text": text,                                  # "Original text before any processing."
            # Publication date of the original text (not related to the processing)
            "original-text-timestamp": "2023-10-01T00:00:00Z",
            "original-url": "https://example.com",                  # URL of the original text
            "summariser-model": "o3-mini",                          # Model used for processing
            "summariser-timestamp": "2023-10-01T00:00:00Z",         # Timestamp of the processing
            "summariser-version": "0.1.0",                          # Version of the code used for the summariser.
            "tcode": "T1001.01",                                    # A MITRE ATT&CK T-Code
            "tcode": T1087.004",                                    # Another MITRE ATT&CK T-Code
            "tcode": "T1548.006",                                   # And another MITRE ATT&CK T-Code
              # TTP of the original text extracted by the AI-based or NLP-based summariser.
            "ttp": "Account Manipulation",
              # Another TTP of the original text extracted by the AI-based or NLP-based summariser.
            "ttp": "Credential Dumping",
            "uuid": "38633d19-123a-4b0f-bc4a-ccb381e58e49",          # UUID of the object
            "version": 1
        }

    The JSON object should be valid and should not contain any additional fields or information.
    Do not invent any information or add any additional fields.
    The JSON object should be formatted as a single line without any line breaks or indentation.

    CTI Report:
    """

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": PROMPT},
                {"role": "user", "content": text},
            ],
            response_format={
                "type": "json_object",
            },
            reasoning_effort="medium",
            # temperature=0,    # for other models
            store=False
        )
        # Extract the relevant information from the response
        if not response.choices:
            raise ValueError("No choices returned from OpenAI API")
        # now get the answer as json / dict:
        data = response.choices[0].message.content
        # Check if the response is valid JSON
        try:
            extract_text = json.loads(data)
        except json.JSONDecodeError:
            print("Invalid JSON response from OpenAI API")
            raise ValueError("Invalid JSON response from OpenAI API")
        # Check if the response contains the expected fields
        expected_fields = [
            "title", "summary", "description", "original-text-timestamp"]
        for field in expected_fields:
            if field not in extract_text:
                print(f"Missing expected field: {field}")
                raise ValueError(f"Missing expected field: {field}")
    except Exception as e:
        print(f"Error calling OpenAI API: {e}")
        raise e
    return extract_text


if __name__ == "__main__":
    # Example usage
    text = """
Russian APT29 hackers' stealthy malware undetected for years
By Ionut Ilascu
January 27, 2022 09:23 AM 0
Cozy Bear Russian hackers camouflage new malware as legitimate files

EXCLUSIVE: Hackers associated with the Russian Federation Foreign Intelligence Service (SVR) continued their incursions on networks of multiple organizations after the SolarWinds supply-chain compromise using two recently discovered sophisticated threats.
The malicious implants are a variant of the GoldMax backdoor for Linux systems and a completely new malware family that cybersecurity company CrowdStrike now tracks as TrailBlazer.
Both threats have been used in StellarParticle campaigns since at least mid-2019 but were identified only two years later, during incident response investigations.
StellarParticle attacks have been attributed to the APT29 hacking group has been running cyber espionage campaigns for more than 12 years and is also known as CozyBear, The Dukes, and Yttrium.

Stealing cookies for MFA bypass
In a report shared exclusively with BleepingComputer, cybersecurity company CrowdStrike today describes in detail the latest tactics, techniques, and procedures (TTPs) observed in cyberattacks from the Cozy Bear state-sponsored hackers.
While some of the techniques are somewhat common today, Cozy Bear has been using them long before they became popular:

credential hopping
hijacking Office 365 (O365) Service Principal and Application
bypassing multi-factor authentication (MFA) by stealing browser cookies
stealing credentials using Get-ADReplAccount
Credential hopping was the first stage of the attack, allowing the threat actor to log into Office 365 from an internal server that the hackers reached through a compromised public-facing system.

CrowdStrike says that this technique is hard to spot in environments with little visibility into identity usage since hackers could use more than one domain administrator account.
Bypassing MFA to access cloud resources by stealing browser cookies has been used since before 2020. CrowdStrike says that APT29 kept a low profile after decrypting the authentication cookies, likely offline, by using the Cookie Editor extension for Chrome to replay them; they deleted the extension afterward.
“This extension permitted bypassing MFA requirements, as the cookies, replayed through the Cookie Editor extension, allowed the threat actor to hijack the already MFA-approved session of a targeted user” - CrowdStrike
This allowed them to move laterally on the network and reach the next stage of the attack, connecting to the victim’s O365 tenant for the next stage of the attack.
CrowdStrike’s report describes the steps that APT29 took to achieve persistence in a position that allowed them to read any email and SharePoint or OneDrive files of the compromised organization.

GoldMax for Linux and TrailBlazer
During their incident response work on APT29 StellarParticle attacks, CrowdStrike’s researchers used the User Access Logging (UAL) database to identify earlier malicious account usage, which led to finding the GoldMax for Linux and TrailBlazer malware.
CrowdStrike says that TrailBlazer is a completely new malware family, while GoldMax for Linux backdoor “is almost identical in functionality and implementation to the previously identified May 2020 Windows variant.”
The researchers believe that the little differences are between the two GoldMax versions are due to the continuous improvements from the developer for long-term detection evasion.
GoldMax was likely used for persistence (a crontab with a “@reboot” line for a non-root user) over long periods in StellarParticle campaigns. The backdoor stayed undetected by posing as a legitimate file in a hidden directory.
The TrailBlazer implant also hid under the name of a legitimate file and it was configured for persistence using the Windows Management Instrumentation (WMI) Event Subscriptions, a relatively new technique in 2019, the earliest known date for its deployment on victim systems.
TrailBlazer managed to keep communication with the command and control (C2) server covert by masking it as legitimate Google Notifications HTTP requests.
CrowdStrike notes that the implant has modular functionality and “a very low prevalence” and that it shares similarities with other malware families used by the same threat actor, such as GoldMax and Sunburst (both used in the SolarWinds supply-chain attack).
Tim Parisi, Director of Professional Services at CrowdStrike, told BleepingComputer that the covert activity of the two malware pieces delayed the discovery of the two malware pieces, as the researchers found them in mid-2021.

Recon and move to Office 365
After gaining access to a target organization’s infrastructure and established persistence, APT29 hackers took every opportunity to collect intelligence that would allow them to further the attack.
One constant tactic was to draw information from the victim’s internal knowledge repositories, the so-called wikis. These documents can hold sensitive details specific to various services and products in the organization.
“This information included items such as product/service architecture and design documents, vulnerabilities and step-by-step instructions to perform various tasks. Additionally, the threat actor viewed pages related to internal business operations such as development schedules and points of contact. In some instances these points of contact were subsequently targeted for further data collection” - CrowdStrike
Parisi told us that accessing company wikis was a common APT29 reconnaissance activity in the investigated StellarParticle attacks.
CrowdStrike’s deep dive into APT29’s StellarParticle campaigns offers details on how the threat actor connected to the victim’s O365 tenant through the Windows Azure Active Directory PowerShell Module, and performed enumeration queries for roles, members, users, domains, accounts, or a service principal's credentials.
When analyzing the log entries, the researchers noticed that the threat actor also executed the AddServicePrincipalCredentials command.
“CrowdStrike analyzed the configuration settings in the victim’s O365 tenant and discovered that a new secret had been added to a built-in Microsoft Azure AD Enterprise Application, Microsoft StaffHub Service Principal, which had Application level permissions” - CrowdSrike
The adversary had added a new secret to the application and set its validity for more than 10 years, the researchers note.
The permission level obtained this way let hackers access all mail and SharePoint/OneDrive files in the company and allowed them to “create new accounts and assign administrator privileges to any account in the organization.”

Maintaining persistence
Once Cozy Bear/APT29 established persistence in a target organization they would maintain it for as long as possible, sometimes helped by the poor security hygiene of the compromised organization.
The longest time the threat actor spent inside an organization was two years, Parisi told BleepingComputer. Persisting this long would not be possible without some effort from the hackers, since organizations often rotate credentials as a security precaution.
To prevent losing access, Cozy Bear hackers would periodically refresh the stolen credentials by stealing new ones, oftentimes via Mimikatz.
In at least one case, though, the administrators of the compromised company reset their passwords to the same ones, thus defeating the purpose of credential rotation.
Cozy Bear hackers are some of the most sophisticated threat actors in the cyber espionage world, with top skills to infiltrate and stay undetected on a company's infrastructure for long periods.
During the StellarParticle attacks, they demonstrated expert knowledge in Azure, Office 365, and Active Directory management.

"""

    result = extract_topics_from_text(text)
    result['uuid'] = str(uuid.uuid4())       # generate a new random UUID
    result['version'] = VERSION
    result["summariser-timestamp"] = datetime.datetime.now().isoformat()  # add the current timestamp
    result["original-url"] = "https://XXXX FIXME"

    print(json.dumps(result, indent=4))
