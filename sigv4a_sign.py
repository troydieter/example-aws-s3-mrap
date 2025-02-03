import boto3
import botocore.auth
import botocore.session
import botocore.awsrequest

class SigV4ASign:
    def __init__(self, session=None):
        self.session = session or boto3.Session()
        self.credentials = self.session.get_credentials()

    def get_headers(self, service, region, request_config):
        request = botocore.awsrequest.AWSRequest(
            method=request_config['method'],
            url=request_config['url'],
            data=request_config.get('data', None)
        )
        signer = botocore.auth.SigV4Auth(self.credentials, service, region)
        signer.add_auth(request)
        return dict(request.headers)