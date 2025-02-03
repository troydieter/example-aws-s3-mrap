import logging
from sigv4a_sign import SigV4ASign
import requests
import os

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Access environment variables
service = 's3'
region = os.getenv('AWS_REGION')
mrap_alias = os.getenv('MRAP_ALIAS')

logger.info(f"Service: {service}, Region: {region}, MRAP Alias: {mrap_alias}")

method = 'PUT'
url = f'https://{mrap_alias}.accesspoint.s3-global.amazonaws.com/test-object'
data = 'hello world'

logger.info(f"Request Method: {method}")
logger.info(f"Request URL: {url}")
logger.info(f"Request Data: {data}")

aws_request_config = {
    'method': 'PUT',
    'url': url,
    'data': data
}

logger.debug(f"AWS Request Config: {aws_request_config}")

try:
    headers = SigV4ASign().get_headers(service, region, aws_request_config)
    logger.debug(f"Generated Headers: {headers}")
except Exception as e:
    logger.error(f"Error generating headers: {str(e)}", exc_info=True)
    raise

try:
    r = requests.put(url, data=data, headers=headers)
    logger.info(f'Response Status Code: {r.status_code}')
    logger.debug(f'Response Headers: {r.headers}')
    logger.debug(f'Response Content: {r.text}')
except requests.exceptions.RequestException as e:
    logger.error(f"Request failed: {str(e)}", exc_info=True)
    raise

print(f'status_code: {r.status_code}')
