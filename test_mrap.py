from sigv4a_sign import SigV4ASign
import requests

service = 's3'
region = '*'
method = 'PUT'
url = f'https://$MRAP_ALIAS.accesspoint.s3-global.amazonaws.com/test-object'
data = 'hello world'

aws_request_config = {
    'method': 'PUT',
    'url': url,
    'data': data
}

headers = SigV4ASign().get_headers(service, region, aws_request_config)
r = requests.put(url, data=data, headers=headers)
print(f'status_code: {r.status_code}')