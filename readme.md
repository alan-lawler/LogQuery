# LogQuery

LogQuery is a web app written in Python using the Dash library. This was part of my capstone project for my BS
degree.

For this project, Syslog-ng receives syslog data from a Sophos XG firewall and writes the logs to disk using the
YYYY-MM-DD.log format. LogQuery monitors a folder for log files matching the current date. It uses regex
to extract log events of internal to external traffic. LoqQuery converts the data to a Pandas dataframe and
uses a lookup function to enrich the log with WHOIS and threat intelligence based on the destination
IP address. LogQuery enriches the logs through various API calls and SQL queries (using S3 SELECT) to a CSV 
file hosted in an AWS S3 bucket.

The project in mainly built using the Dash and Pandas libraries, but it also uses the Boto3, IPAddress,
Requests, geoip2.database, and other various libraries.
