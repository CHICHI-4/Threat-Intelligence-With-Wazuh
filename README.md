# Threat-Intelligence-With-Wazuh
This project aims to analyze and enhance threat intelligence feeds to improve SOC operations by integrating VirusTotal into Wazuh.
The integration of threat intelligence feeds helps analyze and optimize alerts within Wazuh, using the VirusTotal
# Skills Learned
Advanced understanding of SIEM concepts and practical application.
Proficiency in monitoring, analyzing and interpreting alert logs.
Creating custom rule for SIEM to trigger alert and query Virustotal.
Ability to integrate threat intelligence tools in a SIEM using API.
Enhanced threat intelligence IOCs gathering.
Compliance in security operations using cybersecurity frameworks.
Deployment of endpoints to Cloud SIEM.
Navigating through alerts and generating comprehensive reports
# Tools Used
AWS based Security Information and Event Management (SIEM) tool, Wazuh.
Open Source Intelligence Tool, Virustotal.
Windows endpoints to generate alerts.
kali Linux
# Steps
Launch an EC2 instance
Connect to EC2 instance
Update Server using the following command; sudo apt-get update and sudo apt-get upgrade
Download Wazuh and Inst
all using the command; curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
<img width="1712" height="1186" alt="image" src="https://github.com/user-attachments/assets/c8f3c323-ea65-40f3-982b-6588f50ea23c" />
Ref 1: Configuration and installation of agents to Wazuh
<img width="1266" height="1186" alt="image" src="https://github.com/user-attachments/assets/94f40306-ae16-4651-8ff7-6ac12be33479" />
Ref 2: Deployment of agents to Wazuh


Create an account on virustotal to get the API key
<img width="919" height="499" alt="image" src="https://github.com/user-attachments/assets/21ee7e51-4632-4f56-830c-71798a89d969" />

Ref 3: Virustotal account API

Copy the API key and open the configuration file /var/ossec/etc/ossec.conf and add the API key on wazuh server to enable virustotal integration and save.
Go to settings on wazuh manager to confirm the integration of virustotal API key and restart manager.
Enable file integrity monitoring in configuration file to make wazuh to trigger virustotal integration when FIM alert occurs.
<img width="983" height="475" alt="image" src="https://github.com/user-attachments/assets/c7527d43-d9c0-43ad-8ae0-c9f380360432" />

Ref 4: Integration Virustotal API to Wazuh Configuration Manager
<img width="2000" height="1704" alt="image" src="https://github.com/user-attachments/assets/ca9d14d2-e20b-4161-9f05-4e5820d54e6a" />
Ref 5: Wazuh Dashboard for alert monitoring and analysis

Conclusion
In conclusion, this project has highlighted the critical role of enhanced threat intelligence feeds in supporting effective SOC operations. Small enhancements in threat intelligence processing can yield significant improvements. These changes reduce the workload on SOC analysts and empower them to respond to genuine threats more rapidly.

Future work could further explore automation and machine learning techniques, aiming to make threat intelligence feeds even more adaptive to emerging cyber threats. Ultimately, this project contributes to a foundational understanding that enriched, high-quality intelligence feeds are essential for improved SOC operations. As cyber threats evolve, so must the methods of intelligence gathering and processing, making it imperative for SOCs to continuously refine their threat intelligence strategies.

