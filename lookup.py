import boto3
from netaddr import IPAddress
import geoip2.database
import datetime

path = '/home/ubuntu/capstone/src/'

# The lookup function receives log events from log_reader.py and enriches the data with threat intelligence and
# location information. The enriched data is written to a CSV for Dash to convert to a table on a dashboard.
def lookups(d, t, src, dest, dest_port, protocol, action):

    # The category() function accepts the destination IP as a parameter and uses AWS S3 Select to find threat data
    # in a csv file in an AWS S3 bucket. The csv file contains the start and end ip address of various subnets.
    #
    # CSV example:
    # start_ip, end_ip, proxy, tor, vpn
    # 16777218,16777218,,,true

    def category(ip):
        s3 = boto3.client('s3')
        bucket_name = 'ip-threat-list-lib'  # AWS S3 bucket containing csv file
        filename = 'ip-threat-list-upload.csv'  # csv file in AWS S3
        ip = int(IPAddress(ip))  # converts destination IP to an integer

        # SQL query used to determine if the destination IP is between the start and end ip. This also returns ture if
        # the destination IP is == the start_ip or end_ip
        query = f"SELECT start_ip, end_ip, proxy, tor, vpn FROM s3object WHERE '{ip}' BETWEEN start_ip and end_ip"

        resp = s3.select_object_content(
            Bucket=bucket_name,
            Key=filename,
            ExpressionType='SQL',
            Expression=query,
            InputSerialization={'CSV': {"FileHeaderInfo": 'Use'}},
            OutputSerialization={'CSV': {}},
        )

        records = []
        for event in resp['Payload']:
            if 'Records' in event:
                records.append(event['Records']['Payload'].decode("utf-8"))

        # if theat data is found, extract the relevant data
        if len(records) > 0:
            records = records[0].split(',')
            proxy = records[2]
            tor = records[3]
            vpn = records[4].strip()
            results = {'proxy': proxy, 'tor': tor, 'vpn': vpn}

            # deletes results that do not equal true
            for key, value in dict(results).items():
                if value != 'true':
                    del results[key]

            return list(results)
        else:
            return ' '  # returns a blank space if no data is found

    # The location() function accepts the destination IP as a parameter and finds the country in a MaxMind database.
    # The two digit ISO country code is returned along with markdown code to help Dash display flag icons on the
    # dashboard.
    def location(ip):
        reader = geoip2.database.Reader('/home/ubuntu/maxmind/GeoIP2-Country_20210323/GeoIP2-Country.mmdb')
        response = reader.country(ip)
        if response is None:
            return ''  # returns a blank string if nothing is found
        else:
            return response.country.iso_code

    cat = category(dest)
    cat = str(cat).strip("[]'")
    geo = location(dest)

    # two digit ISO country code and markup code for flag images
    country = f'{geo} ![](../assets/svg/{geo.lower()}.png#thumbnail)'

    # each enriched log event is written to a CSV file for Dash to display on a dashboard
    with open(path + str(datetime.date.today()) + '.csv', 'a') as file:
        file.write(f'{d},{t},{src},{dest},{dest_port},{protocol},{action},{cat},{country}\n')


# for testing
# lookups('2021-03-31', '00:27:10', '10.10.10.10', '1.0.202.57', '443', 'TCP', 'block')
