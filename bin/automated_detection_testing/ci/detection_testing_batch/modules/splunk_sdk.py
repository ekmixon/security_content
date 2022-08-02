import sys
from time import sleep
import splunklib.results as results
import splunklib.client as client
import splunklib.results as results
import requests

def test_baseline_search(splunk_host, splunk_password, search, pass_condition, baseline_name, baseline_file, earliest_time, latest_time):
    try:
        service = client.connect(
            host=splunk_host,
            port=8089,
            username='admin',
            password=splunk_password
        )
    except Exception as e:
        print(f"Unable to connect to Splunk instance: {str(e)}")
        return 1, {}

    # search and replace \\ with \\\
    # search = search.replace('\\','\\\\')

    search = search if search.startswith('|') else f'search {search}'
    kwargs = {"exec_mode": "blocking",
              "dispatch.earliest_time": earliest_time,
              "dispatch.latest_time": latest_time}

    splunk_search = f'{search} {pass_condition}'

    try:
        job = service.jobs.create(splunk_search, **kwargs)
    except Exception as e:
        print(f"Unable to execute baseline: {str(e)}")
        return 1, {}

    test_results = {
        'diskUsage': job['diskUsage'],
        'runDuration': job['runDuration'],
        'baseline_name': baseline_name,
        'baseline_file': baseline_file,
        'scanCount': job['scanCount'],
    }

    if int(job['resultCount']) != 1:
        print(f"Test failed for baseline: {baseline_name}")
        test_results['error'] = True
    else:
        print(f"Test successful for baseline: {baseline_name}")
        test_results['error'] = False

    return test_results


def test_detection_search(splunk_host, splunk_password, search, pass_condition, detection_name, detection_file, earliest_time, latest_time):
    try:
        service = client.connect(
            host=splunk_host,
            port=8089,
            username='admin',
            password=splunk_password
        )
    except Exception as e:
        print(f"Unable to connect to Splunk instance: {str(e)}")
        return 1, {}

    # search and replace \\ with \\\
    # search = search.replace('\\','\\\\')

    search = search if search.startswith('|') else f'search {search}'
    kwargs = {"exec_mode": "blocking",
              "dispatch.earliest_time": "-1d",
              "dispatch.latest_time": "now"}

    splunk_search = f'{search} {pass_condition}'

    try:
        job = service.jobs.create(splunk_search, **kwargs)
    except Exception as e:
        print(f"Unable to execute detection: {str(e)}")
        return 1, {}

    test_results = {
        'diskUsage': job['diskUsage'],
        'runDuration': job['runDuration'],
        'detection_name': detection_name,
        'detection_file': detection_file,
        'scanCount': job['scanCount'],
    }

    if int(job['resultCount']) != 1:
        print(f"Test failed for detection: {detection_name}")
        test_results['error'] = True
    else:
        print(f"Test successful for detection: {detection_name}")
        test_results['error'] = False

    return test_results


def delete_attack_data(splunk_host, splunk_password):
    try:
        service = client.connect(
            host=splunk_host,
            port=8089,
            username='admin',
            password=splunk_password
        )
    except Exception as e:
        print(f"Unable to connect to Splunk instance: {str(e)}")
        return 1, {}

    splunk_search = 'search index=test* | delete'

    kwargs = {"exec_mode": "blocking",
              "dispatch.earliest_time": "-1d",
              "dispatch.latest_time": "now"}

    try:
        job = service.jobs.create(splunk_search, **kwargs)
    except Exception as e:
        print(f"Unable to execute search: {str(e)}")
        return 1, {}