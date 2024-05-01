# Malcheck

Malcheck serves as an initial response tool for threat hunting, providing rapid triage for a variety of potential threats including malware samples, URLs, IP addresses, domains, malware families, IOCs, and hashes. It acts as a client to various existing sandboxes, facilitating dynamic and static behavior reports, sample submission, and download from multiple endpoints.

The tool's objectives include:

Identifying similar executable malware samples (PE/PE+) based on import table signatures (imphash) and organizing them with distinct color coding.
Fetching hash information from VirusTotal, Hybrid Analysis, Malshare, Polyswarm, URLhaus, Alien Vault, Malpedia, and ThreatCrowd engines.
Determining the presence of overlays in malware samples and optionally extracting them.
Checking suspect files on VirusTotal, Hybrid Analysis, and Polyswarm.
Verifying URLs on VirusTotal, Malshare, Polyswarm, URLhaus, and Alien Vault engines.
Downloading malware samples from Hybrid Analysis, Malshare, URLHaus, Polyswarm, and Malpedia engines.
Submitting malware samples to VirusTotal, Hybrid Analysis, and Polyswarm.
Listing recent suspected URLs from URLHaus.
Listing recent payloads from URLHaus.
Searching for specific payloads on Malshare.
Identifying similar payloads (PE32/PE32+) on the Polyswarm engine.
Classifying all files in a directory by querying information from VirusTotal and Hybrid Analysis.
Generating reports about a suspicious domain using engines such as VirusTotal, Malpedia, and ThreatCrowd.
Checking APK packages directly from Android devices against Hybrid Analysis and VirusTotal.
Submitting APK packages directly from Android devices to Hybrid Analysis and VirusTotal.


