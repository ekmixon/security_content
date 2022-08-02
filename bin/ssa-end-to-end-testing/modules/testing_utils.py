import os
import sys
import logging
import coloredlogs
#import urllib.request
from requests import get
import yaml

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(coloredlogs.ColoredFormatter("%(asctime)s - %(levelname)s - %(message)s%(detail)s"))
logger.addHandler(handler)


def get_path(p):
    return os.path.join(os.path.join(os.path.dirname(__file__), "..", p))


def log(level, msg, detail=None):
    args = {'detail': ""} if detail is None else {'detail': "\n%s" % detail}
    logger.log(level, msg, extra=args)


def get_detection(unit_test):
    with open(get_path(f"../detections/{unit_test['file']}")) as detection_fh:
        return yaml.safe_load(detection_fh)


def pull_data(test, destination):
    data_desc = {}
    if 'attack_data' in test:
        for d in test['attack_data']:
            test_data = f"{destination}/{d['file_name']}"
            #urllib.request.urlretrieve(d['data'], test_data)
            with open(test_data, 'wb') as f:
                f.write(get(d['data']).content)
            data_desc[d['file_name']] = test_data
            log(logging.DEBUG, f"Downloading dataset {d['file_name']} from {d['data']}")
    return data_desc
