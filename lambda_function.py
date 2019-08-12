import json
import logging
import time
import boto3

from collections import namedtuple
from typing import Union

ResourceRecord = namedtuple('ResourceRecord', 'name value')


class AcmClient:

    def __init__(self, delay=1):
        self.acm = boto3.client('acm')
        self.delay = delay
        self.log = logging.getLogger(__name__)
        self.log.setLevel(logging.DEBUG)

    def describe_certificate(self, certificate_arn: str) -> dict:
        certificate_info = self.acm.describe_certificate(CertificateArn=certificate_arn)

        if 'Certificate' in certificate_info:
            certificate = certificate_info['Certificate']
            if 'DomainValidationOptions' in certificate:
                options = certificate['DomainValidationOptions']
                if len(options):
                    return options[0]
        return {}

    def get_resource_record(self, certificate_arn: str) -> dict:
        self.log.info('describe certificate arn:%s' % certificate_arn)

        validation_option = self.describe_certificate(certificate_arn)
        self.log.debug(validation_option)

        while 'ResourceRecord' not in validation_option:
            self.log.info(("wait for adding 'ResourceRecord' to "
                           "'DomainValidationOptions':%s") % certificate_arn)
            time.sleep(self.delay)
            validation_option = self.describe_certificate(certificate_arn)
            self.log.debug(validation_option)

        record = ResourceRecord(validation_option['ResourceRecord']['Name'],
                                validation_option['ResourceRecord']['Value'])
        self.log.info('describe successfully %s' % record)
        return record

    def request_certificate(self, domain: str) -> Union[ResourceRecord, str]:
        """register certificate to ALB(so needs Available ALB as a prerequisite).

        Args:
            domain (str): domain name of certificate

        Returns:
            Re: [description]
        """
        if not domain:
            return 'empty domain. skip to request certificate.'

        self.log.info('request certificate %s' % domain)
        certificate = self.acm.request_certificate(DomainName=domain,
                                                   ValidationMethod='DNS')
        self.log.info('certificate created %s' % domain)
        self.log.debug(certificate)

        certificate_arn = certificate['CertificateArn']
        try:
            resource_record = self.get_resource_record(certificate_arn)
        except Exception:
            msg = ('failed to describe certificate.'
                   ' certificate_arn: %s') % certificate_arn
            self.log.error(msg, exc_info=True)
            return 'failed to describe certificate. certificate_arn: %s'

        return resource_record


def lambda_handler(event, context):
    # create logger
    logger = logging.getLogger('lambda_handler')
    logger.setLevel(logging.INFO)
    logger.info('start to request certificate.')
    logger.info('%s' % event)

    if ('domain' not in event) or (not event['domain']):
        return {
            'statusCode': 400,
            'body': json.dumps('empty domain. skip to request certificate.')
        }

    acm_client = AcmClient()
    result = acm_client.request_certificate(event['domain'])

    status_code = 200 if type(result) == ResourceRecord else 500
    return {'statusCode': status_code, 'body': json.dumps(result)}
