from .base import BaseCloudProvider


class AWS(BaseCloudProvider):
    domains = [
        "amazon-dss.com",
        "amazonaws.com",
        "amazonaws.com.cn",
        "amazonaws.org",
        "amazonses.com",
        "amazonwebservices.com",
        "aws",
        "aws.a2z.com",
        "aws.amazon.com",
        "aws.dev",
        "awsstatic.com",
        "elasticbeanstalk.com",
    ]
    bucket_name_regex = r"[a-z0-9_][a-z0-9-\.]{1,61}[a-z0-9]"
    regexes = {"STORAGE_BUCKET": [r"(" + bucket_name_regex + r")\.(s3-?(?:[a-z0-9-]*\.){1,2}amazonaws\.com)"]}
