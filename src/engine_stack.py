import re
import time
import json
import redis
import urllib
import string

import cpe as cpe_module

from utils import *

class SearchEngineStacks(object):

    def __init__(self, SETTINGS):
        self.SETTINGS = SETTINGS
        self.cache_for_indexer = redis.StrictRedis(
            host=SETTINGS["cache_for_indexer"]["host"],
            port=SETTINGS["cache_for_indexer"]["port"],
            db=SETTINGS["cache_for_indexer"]["db"])
        pass

    @staticmethod
    def serialize(element):
        try:
            return json.dumps(element)
        except:
            return None

    @staticmethod
    def deserialize(element):
        try:
            return json.loads(element)
        except:
            return None

    def create_collection_name_by_component_and_version(self, component, version=None):
        if version is None:
            version = "*"
        collection_name = "".join([
            self.SETTINGS["collection_for_index"],
            component,
            "::",
            version
        ])
        return collection_name

    def check_if_item_already_in_index_by_component_and_version(self, item_to_check):
        collection_name = "".join([
            self.SETTINGS["collection_for_index"],
            item_to_check["component"],
            "::",
            item_to_check["version"]
        ])
        result = self.cache_for_indexer.llen(collection_name)
        if result == 0:
            return False
        return True

    def get_all_cache_elements_as_list_of_jsons(self, collection_name, clear_it=True):
        items_in_cache = self.cache_for_indexer.lrange(collection_name, 0, -1)
        list_of_elements = []
        for element in items_in_cache:
            list_of_elements.append(
                self.deserialize(
                    element))
        if clear_it:
            self.cache_for_indexer.delete(collection_name)
        return list_of_elements

    def save_list_of_elements_into_cache(self, collection_name, list_to_save=[]):
        for element in list_to_save:
            self.cache_for_indexer.rpush(
                collection_name,
                self.serialize(element))

    def verify_if_component_and_version_is_valid(self, item_to_verify, only_digits__and_dot_in_version=False):
        if item_to_verify["version"] is not None:
            if item_to_verify["version"] == "":
                return None
            try:
                item_to_verify["version"] = urllib.parse.unquote(item_to_verify["version"])
            except:
                pass
            try:
                item_to_verify["component"] = urllib.parse.unquote(item_to_verify["component"])
            except:
                pass
            if only_digits__and_dot_in_version:
                allow = string.digits + '.' + '(' + ')'
                item_to_verify["version"] = re.sub('[^%s]' % allow, '', item_to_verify["version"])
            return item_to_verify
        return None

    @staticmethod
    def extract_component_and_version_from_cpe_string(cpe_string):
        result = None
        try:
            cpep = cpe_module.CPE(cpe_string, cpe_module.CPE.VERSION_2_2)
        except:
            try:
                cpep = cpe_module.CPE(cpe_string, cpe_module.CPE.VERSION_2_3)
            except:
                try:
                    cpep = cpe_module.CPE(cpe_string, cpe_module.CPE.VERSION_UNDEFINED)
                except:
                    cpep = None
        if cpep is not None:
            c22_product = cpep.get_product() if cpep is not None else []
            c22_version = cpep.get_version() if cpep is not None else []
            result = dict()
            result["component"] = c22_product[0] if isinstance(c22_product, list) and len(c22_product) > 0 else None
            result["version"] = c22_version[0] if isinstance(c22_version, list) and len(c22_version) > 0 else None
        if result["component"] is None or result["version"] is None:
            result = None
        if result["component"] == "" or result["version"] == "":
            result = None
        return result

    def append_item_in_index(self, item_to_update):
        collection_name = self.create_collection_name_by_component_and_version(
            component=item_to_update["component"],
            version=item_to_update["version"]
        )

        items_in_cache = self.get_all_cache_elements_as_list_of_jsons(collection_name, clear_it=True)

        items_to_save = []

        if len(items_in_cache) == 0:
            items_to_save.append(
                item_to_update
            )
        else:
            for one_item in items_in_cache:
                element = one_item.copy()
                if element["id"] == item_to_update["id"]:
                    element.update(item_to_update)
                items_to_save.append(
                    element
                )
                del element

        self.save_list_of_elements_into_cache(collection_name, items_to_save)

    def update_items_in_cache_index(self, items_to_update):
        count = 0

        if isinstance(items_to_update, list):
            for one_item in items_to_update:

                one_item_in_json = json.loads(one_item)

                cpe_strings = one_item_in_json["cpe"]["data"]

                for one_cpe_string in cpe_strings:
                    component_and_version = self.extract_component_and_version_from_cpe_string(one_cpe_string)
                    if component_and_version is not None:
                        result_of_verify = self.verify_if_component_and_version_is_valid(component_and_version)
                        if result_of_verify is not None:
                            one_item_in_json["component"] = result_of_verify["component"]
                            one_item_in_json["version"] = result_of_verify["version"]
                            self.append_item_in_index(one_item_in_json)

                    count += 1
                pass
            pass

        return count

    def find_by_component_and_version(self, component, version):
        collection = self.create_collection_name_by_component_and_version(component=component, version=version)
        list_of_components = self.get_all_cache_elements_as_list_of_jsons(collection, clear_it=False)
        return list_of_components

    pass

    pass

    pass

    def action_update_cve_modified(self):
        result = dict(
            count=0,
            time_delta=0,
            message=""
        )

        start_time = time.time()

        modified_items, response = download_cve_file(self.SETTINGS["sources"]["cve_modified"])
        modified_parsed = parse_cve_file(modified_items)

        count = self.update_items_in_cache_index(modified_parsed)
        time_delta = time.time() - start_time

        result["count"] = count
        result["time_delta"] = time_delta
        result["message"] = "Complete process {} modified items at {} sec.".format(
            count,
            time_delta
        )
        return result

    def action_update_cve_recent(self):
        result = dict(
            count=0,
            time_delta=0,
            message=""
        )

        start_time = time.time()

        recent_items, response = download_cve_file(self.SETTINGS["sources"]["cve_recent"])
        recent_parsed = parse_cve_file(recent_items)

        count = self.update_items_in_cache_index(recent_parsed)
        time_delta = time.time() - start_time

        result["count"] = count
        result["time_delta"] = time_delta
        result["message"] = "Complete process {} recent items at {} sec.".format(
            count,
            time_delta
        )
        return result

    def cve_loop(self, parsed_item):
        count = 0

        count = self.update_items_in_cache_index(parsed_item)

        return count

    def action_populate_cve(self):
        result = dict(
            count=0,
            time_delta=0,
            message=""
        )
        count = 0
        start_time = time.time()

        current_year = datetime.now().year
        for year in range(self.SETTINGS["start_year"], current_year + 1):
            start_time = time.time()
            source = self.SETTINGS["sources"]["cve_base"] + str(year) + self.SETTINGS["sources"]["cve_base_postfix"]
            cve_item, response = download_cve_file(source)
            parsed_cve_item = parse_cve_file(cve_item)

            count += self.cve_loop(parsed_cve_item)

            print("Populate CVE-{} takes {} sec.".format(year, time.time() - start_time))

        time_delta = time.time() - start_time

        result["count"] = count
        result["time_delta"] = time_delta
        result["message"] = "Complete process {} populated items at {} sec.".format(
            count,
            time_delta
        )
        return result