import sys
import time

from engine_hash import SearchEngineHashes
from engine_stack import SearchEngineStacks

##############################################################################

SETTINGS = dict(
    sources = dict(
        cve_modified="https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz",
        cve_recent="https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz",
        cve_base="https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-",
        cve_base_postfix=".json.gz",
        cpe22="https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.2.xml.zip",
        cpe23="https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip",
        cwe="http://cwe.mitre.org/data/xml/cwec_v2.8.xml.zip",
        capec="http://capec.mitre.org/data/xml/capec_v2.6.xml",
        ms="http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx",
        d2sec="http://www.d2sec.com/exploits/elliot.xml",
        npm="https://api.nodesecurity.io/advisories",
    ),
    cache_for_indexer = dict(
        host="localhost",
        port=6379,
        db=1
    ),
    collection_for_index="indexer::",
    start_year=2002,

)

##############################################################################

def print_as_list(to_print):
    for element in list(to_print):
        print(element)

##############################################################################

def main():

    start_global = time.time()

    engine_stacks = SearchEngineStacks(SETTINGS=SETTINGS)

    print(engine_stacks.action_populate_cve()["message"])
    print(engine_stacks.action_update_cve_modified()["message"])
    print(engine_stacks.action_update_cve_recent()["message"])


    start = time.time()
    print_as_list(engine_stacks.find_by_component_and_version("openssl", "1.0*"))
    print('Search Time is: {}'.format(time.time() - start))
    pass
    print('Global time is: {}'.format(time.time() - start_global))

if __name__ == '__main__':
    sys.exit(main())
