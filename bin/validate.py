#!/usr/bin/python

'''
Validates Manifest file under the security_content repo for correctness.
'''

import glob
import json
import jsonschema
import yaml
import sys
import argparse
import datetime
import string
import re
from pathlib import Path
from os import path, walk


def validate_schema(REPO_PATH, type, objects, verbose):

    error = False
    errors = []

    schema_file = path.join(path.expanduser(REPO_PATH), f'spec/{type}.spec.json')

    try:
        schema = json.loads(open(schema_file, 'rb').read())
    except IOError:
        print("ERROR: reading schema file {0}".format(schema_file))

    manifest_files = []
    for root, dirs, files in walk(f"{REPO_PATH}/{type}"):
        manifest_files.extend(
            path.join(root, file) for file in files if file.endswith(".yml")
        )

    for manifest_file in manifest_files:
        if verbose:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                errors.append("ERROR: Error reading {0}".format(manifest_file))
                error = True
                continue

        validator = jsonschema.Draft7Validator(schema, format_checker=jsonschema.FormatChecker())
        for schema_error in validator.iter_errors(object):
            errors.append("ERROR: {0} at:\n\t{1}".format(json.dumps(schema_error.message), manifest_file))
            error = True

        if type in objects:
            objects[type].append(object)
        else:
            arr = [object]
            objects[type] = arr

    return objects, error, errors


def validate_objects(REPO_PATH, objects, verbose):

    # uuids
    uuids = []
    errors = []

    for lookup in objects['lookups']:
        errors = errors + validate_lookups_content(REPO_PATH, "lookups/%s", lookup)

    objects_array = objects['stories'] + objects['detections']
    for object in objects_array:
        validation_errors, uuids = validate_standard_fields(object, uuids)
        errors = errors + validation_errors

    for object in objects['detections']:
        if 'Splunk Behavioral Analytics' not in object['tags']['product']:
            errors = errors + validate_detection_search(object, objects['macros'])
            errors = errors + validate_fields(object)

    for object in objects['tests']:
        errors = errors + validate_tests(REPO_PATH, object)

    return errors


def validate_fields(object):
    errors = []

    if object['type'] not in ['TTP', 'Anomaly', 'Hunting', 'Baseline', 'Investigation', 'Correlation']:
        errors.append(
            f"ERROR: invalid type [TTP, Anomaly, Hunting, Baseline, Investigation, Correlation] for object: {object['name']}"
        )


    if 'tags' in object:

        # check if required_fields is present
        if 'required_fields' not in object['tags']:
            errors.append(
                f"ERROR: a `required_fields` tag is required for object: {object['name']}"
            )


        if 'security_domain' not in object['tags']:
            errors.append(
                f"ERROR: a `security_domain` tag is required for object: {object['name']}"
            )


        if object['type'] == 'streaming' and 'risk_severity' not in object['tags']:
            errors.append(
                f"ERROR: a `risk_severity` tag is required for object: {object['name']}"
            )


    return errors


def validate_standard_fields(object, uuids):

    errors = []

    if object['id'] == '':
        errors.append(f"ERROR: Blank ID for object: {object['name']}")

    if object['id'] in uuids:
        errors.append(f"ERROR: Duplicate UUID found for object: {object['name']}")
    else:
        uuids.append(object['id'])

    if (
        'products' in object['tags']
        and 'Splunk Behavioral Analytics' not in object['tags']['products']
        and len(object['name']) > 75
    ):
        errors.append(
            f"ERROR: Search name is longer than 75 characters: {object['name']}"
        )


    # if object['name'].endswith(" "):
    #     errors.append(
    #         "ERROR: name has trailing spaces: '%s'" %
    #         object['name'])

    invalidChars = set(string.punctuation.replace("-", ""))
    if any(char in invalidChars for char in object['name']):
        errors.append(
            f"ERROR: No special characters allowed in name for object: {object['name']}"
        )


    try:
        object['description'].encode('ascii')
    except UnicodeEncodeError:
        errors.append(f"ERROR: description not ascii for object: {object['name']}")

    if 'how_to_implement' in object:
        try:
            object['how_to_implement'].encode('ascii')
        except UnicodeEncodeError:
            errors.append(
                f"ERROR: how_to_implement not ascii for object: {object['name']}"
            )


    try:
        datetime.datetime.strptime(object['date'], '%Y-%m-%d')
    except ValueError:
        errors.append(
            f"ERROR: Incorrect date format, should be YYYY-MM-DD for object: {object['name']}"
        )


    # logic for handling risk related tags which are a triple of k/v pairs
    # risk_object, risk_object_type and risk_score
    # the first two fields risk_object, and risk_object_type are an enum of fixed values
    # defined by ESCU risk scoring

    if 'tags' in object:
        # check product tag is present in all objects
        if 'product' not in object['tags']:
            errors.append(
                f"ERROR: a `product` tag is required for object: {object['name']}"
            )


        for k,v in object['tags'].items():

            if k == 'confidence':
                if not isinstance(v, int):
                    errors.append(f"ERROR: confidence not integer value for object: {v}")
            elif k == 'impact':
                if not isinstance(v, int):
                    errors.append(f"ERROR: impact not integer value for object: {v}")

            elif k == 'risk_score':
                if not isinstance(v, int):
                    errors.append(f"ERROR: risk_score not integer value for object: {v}")

        if 'impact' in object['tags'] and 'confidence' in object['tags']:
            calculated_risk_score = int(((object['tags']['impact'])*(object['tags']['confidence']))/100)
            if calculated_risk_score != object['tags']['risk_score']:
                errors.append(
                    f"ERROR: risk_score not calulated correctly and it should be set to {calculated_risk_score} for "
                    + object['name']
                )

    return errors, uuids


def validate_detection_search(object, macros):
    errors = []

    if object['type'] not in ["Baseline", "Investigation"]:
        if '_filter' not in object['search']:
            errors.append("ERROR: Missing filter for detection: " + object['name'])
    elif object['type'] == "Baseline":
        if 'deployments' not in object['tags']:
            errors.append("ERROR: Baseline need a corresponsing deployments: " + object['name'])

    filter_macro = re.search("([a-z0-9_]*_filter)", object['search'])

    if (
        filter_macro
        and filter_macro[1]
        != object['name']
        .replace(' ', '_')
        .replace('-', '_')
        .replace('.', '_')
        .replace('/', '_')
        .lower()
        + '_filter'
        and "input_filter" not in filter_macro[1]
    ):
        errors.append("ERROR: filter for detection: " + object['name'] + " needs to use the name of the detection in lowercase and the special characters needs to be converted into _ .")

    if (
        any(
            x in object['search']
            for x in ['eventtype=', 'sourcetype=', ' source=', 'index=']
        )
        and 'index=_internal' not in object['search']
    ):
        errors.append("ERROR: Use source macro instead of eventtype, sourcetype, source or index in detection: " + object['name'])

    macros_found = re.findall('\`([^\s]+)`',object['search'])
    macros_filtered = [
        macro
        for macro in macros_found
        if '_filter' not in macro
        and 'security_content_ctime' not in macro
        and 'drop_dm_object_name' not in macro
        and 'cim_' not in macro
        and 'get_' not in macro
    ]

    for macro in macros_filtered:
        found_macro = any(macro_obj['name'] == macro for macro_obj in macros)
        if not found_macro:
            errors.append(
                f"ERROR: macro definition for {macro}"
                + " can't be found for detection "
                + object['name']
            )


    return errors


def validate_lookups_content(REPO_PATH, lookup_path, lookup):
    errors = []
    if 'filename' in lookup:
        lookup_csv_file = path.join(path.expanduser(REPO_PATH), lookup_path % lookup['filename'])
        if not path.isfile(lookup_csv_file):
            errors.append(f"ERROR: filename {lookup['filename']} does not exist")

    return errors


def validate_tests(REPO_PATH, object):
    errors = []

    # check detection file exists
    for test in object['tests']:
        if 'file' in test:
            detection_file_path = Path(f'{REPO_PATH}/detections/' + test['file'])
            if not detection_file_path.is_file():
                errors.append('ERROR: orphaned test: {0}, detection file: {1} no longer exists or incorrect detection path under `file`'.format(object['name'], detection_file_path))
        else:
            errors.append('ERROR: test: {0} does not have a detection `file` associated with detection: {1}'.format(object['name'], test['name']))
            #test['file']
    return errors

def main(REPO_PATH, verbose):

    validation_objects = ['macros','lookups','stories','detections','deployments', 'tests']

    objects = {}
    schema_error = False
    schema_errors = []

    for validation_object in validation_objects:
        objects, error, errors = validate_schema(REPO_PATH, validation_object, objects, verbose)
        schema_error = schema_error or error
        if len(errors) > 0:
            schema_errors = schema_errors + errors

    validation_errors = validate_objects(REPO_PATH, objects, verbose)

    schema_errors = schema_errors + validation_errors

    for schema_error in schema_errors:
        print(schema_error)

    if schema_error or len(schema_errors) > 0:
        sys.exit("Errors found")
    else:
        print("No Errors found")


if __name__ == "__main__":
    # grab arguments
    parser = argparse.ArgumentParser(description="validates security content manifest files", epilog="""
        Validates security manifest for correctness, adhering to spec and other common items.""")
    parser.add_argument("-p", "--path", required=True, help="path to security-security content repo")
    parser.add_argument("-v", "--verbose", required=False, action='store_true', help="prints verbose output")
    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    verbose = args.verbose

    main(REPO_PATH, verbose)
