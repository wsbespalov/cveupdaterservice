import json
import urllib.request as req
import zipfile
from io import BytesIO
import gzip
import bz2
from datetime import datetime
from dateutil.parser import parse as parse_datetime


from cve_item import CVEItem


def download_cve_file(source):
    file_stream, response_info = get_file(source)
    try:
        result = json.load(file_stream)
        if "CVE_Items" in result:
            return result["CVE_Items"], response_info
        return None
    except json.JSONDecodeError as json_error:
        print('Get an JSON decode error: {}'.format(json_error))
        return None


def parse_cve_file(items=None):
    if items is None:
        items = []
    parsed_items = []
    for item in items:
        parsed_items.append(CVEItem(item).to_json())
    return parsed_items


def unify_time(dt):
    if isinstance(dt, str):
        if 'Z' in dt:
            dt = dt.replace('Z', '')
        return parse_datetime(dt)

    if isinstance(dt, datetime):
        return parse_datetime(str(dt))


def unify_bool(param):
    if isinstance(param, bool):
        if param is False:
            return 'false'
        elif param is True:
            return 'true'
    elif isinstance(param, str):
        if param == 'False':
            return 'false'
        elif param == 'True':
            return 'true'
        elif param == '':
            return 'false'
    elif isinstance(param, type(None)):
        return 'false'

def get_file(getfile, unpack=True, raw=False, HTTP_PROXY=None):
    try:
        if HTTP_PROXY:
            proxy = req.ProxyHandler({'http': HTTP_PROXY, 'https': HTTP_PROXY})
            auth = req.HTTPBasicAuthHandler()
            opener = req.build_opener(proxy, auth, req.HTTPHandler)
            req.install_opener(opener)

        data = response = req.urlopen(getfile)

        if raw:
            return data

        if unpack:
            if 'gzip' in response.info().get('Content-Type'):
                buf = BytesIO(response.read())
                data = gzip.GzipFile(fileobj=buf)
            elif 'bzip2' in response.info().get('Content-Type'):
                data = BytesIO(bz2.decompress(response.read()))
            elif 'zip' in response.info().get('Content-Type'):
                fzip = zipfile.ZipFile(BytesIO(response.read()), 'r')
                length_of_namelist = len(fzip.namelist())
                if length_of_namelist > 0:
                    data = BytesIO(fzip.read(fzip.namelist()[0]))
        return data, response
    except Exception as ex:
        return None, str(ex)