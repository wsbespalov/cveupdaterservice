import json
from datetime import datetime

class CVEItem(object):

    def __init__(self, data):
        """
        Parse JSON data structure for ONE item
        :param data: (dict) - Item to parse
        """
        cve = data.get("cve", {})

        # Get Data Type -> str
        self.data_type = cve.get("data_type", None)
        # Get Data Format -> str
        self.data_format = cve.get("data_format", None)
        # Get Data Version -> str
        self.data_version = cve.get("data_version", None)  # Data version like 4.0
        # Get CVE ID like CVE-2002-2446 -> str
        CVE_data_meta = cve.get("CVE_data_meta", {})
        self.id = CVE_data_meta.get("ID", None)
        # Get Vendor -> JSON with list -> {"data": vendor_data}
        affects = cve.get("affects", {})
        vendor = affects.get("vendor", {})
        vendor_data = []
        vdata = vendor.get("vendor_data", [])
        for vd in vdata:
            vendor_name = vd.get("vendor_name", None)  # vendor name - one value - VENDOR
            product = vd.get("product", {})
            product_data = product.get("product_data", [])
            for pd in product_data:
                product_name = pd.get("product_name", None)  # product name - list of products for VENDOR
                version = pd.get("version", {})
                version_data = version.get("version_data", [])
                for vd in version_data:
                    version_value = vd.get("version_value", None)  # version value list of versions for PRODUCT
                    # create json set
                    if version_value is not None and product_name is not None and vendor_name is not None:
                        jtemplate = dict(
                            vendor=vendor_name,
                            product=product_name,
                            version=version_value
                        )
                        vendor_data.append(jtemplate)
                        del jtemplate
        self.vendor = {"data": vendor_data}
        # GET CWEs -> JSON with list -> {"data": cwe}
        cwe = []
        problemtype = cve.get("problemtype", {})
        problemtype_data = problemtype.get("problemtype_data", [])
        for pd in problemtype_data:
            description = pd.get("description", [])
            for d in description:
                value = d.get("value", None)
                if value is not None:
                    cwe.append(value)
        self.cwe = {"data": cwe}
        # GET RREFERENCES -> JSON with list -> {"data": references}
        references = []
        ref = cve.get("references", {})
        reference_data = ref.get("reference_data", [])
        for rd in reference_data:
            url = rd.get("url", None)
            if url is not None:
                references.append(url)
        self.references = {"data": references}
        # GET DESCRIPTION -> str
        self.description = ""
        descr = cve.get("description", {})
        description_data = descr.get("description_data", [])
        for dd in description_data:
            value = dd.get("value", "")
            self.description = self.description + value
        # GET cpe -> JSON with list -> {"data": cpe22}
        cpe22 = []
        conf = data.get("configurations", {})
        nodes = conf.get("nodes", [])
        for n in nodes:
            cpe = n.get("cpe", [])
            for c in cpe:
                c22 = c.get("cpe22Uri", None)
                cpe22.append(c22)
        self.cpe = {"data": cpe22}

        impact = data.get("impact", {})

        # GET CVSSV2
        self.cvssv2 = {}
        baseMetricV2 = impact.get("baseMetricV2", {})
        cvssV2 = baseMetricV2.get("cvssV2", {})
        self.cvssv2["version"] = cvssV2.get("version", "")
        self.cvssv2["vectorString"] = cvssV2.get("vectorString", "")
        self.cvssv2["accessVector"] = cvssV2.get("accessVector", "")
        self.cvssv2["accessComplexity"] = cvssV2.get("accessComplexity", "")
        self.cvssv2["authentication"] = cvssV2.get("authentication", "")
        self.cvssv2["confidentialityImpact"] = cvssV2.get("confidentialityImpact", "")
        self.cvssv2["integrityImpact"] = cvssV2.get("integrityImpact", "")
        self.cvssv2["availabilityImpact"] = cvssV2.get("availabilityImpact", "")
        self.cvssv2["baseScore"] = cvssV2.get("baseScore", "")
        self.cvssv2["severity"] = baseMetricV2.get("severity", "")
        self.cvssv2["exploitabilityScore"] = baseMetricV2.get("exploitabilityScore", "")
        self.cvssv2["impactScore"] = baseMetricV2.get("impactScore", "")
        self.cvssv2["obtainAllPrivilege"] = baseMetricV2.get("obtainAllPrivilege", "")
        self.cvssv2["obtainUserPrivilege"] = baseMetricV2.get("obtainUserPrivilege", "")
        self.cvssv2["obtainOtherPrivilege"] = baseMetricV2.get("obtainOtherPrivilege", "")
        self.cvssv2["userInteractionRequired"] = baseMetricV2.get("userInteractionRequired", "")

        # GET CVSSV3
        self.cvssv3 = {}
        baseMetricV3 = impact.get("baseMetricV3", {})
        cvssV3 = baseMetricV3.get("cvssV3", {})
        self.cvssv3["version"] = cvssV3.get("version", "")
        self.cvssv3["vectorString"] = cvssV3.get("vectorString", "")
        self.cvssv3["attackVector"] = cvssV3.get("attackVector", "")
        self.cvssv3["attackComplexity"] = cvssV3.get("attackComplexity", "")
        self.cvssv3["privilegesRequired"] = cvssV3.get("privilegesRequired", "")
        self.cvssv3["userInteraction"] = cvssV3.get("userInteraction", "")
        self.cvssv3["scope"] = cvssV3.get("scope", "")
        self.cvssv3["confidentialityImpact"] = cvssV3.get("confidentialityImpact", "")
        self.cvssv3["integrityImpact"] = cvssV3.get("integrityImpact", "")
        self.cvssv3["availabilityImpact"] = cvssV3.get("availabilityImpact", "")
        self.cvssv3["baseScore"] = cvssV3.get("baseScore", "")
        self.cvssv3["baseSeverity"] = cvssV3.get("baseSeverity", "")
        self.cvssv3["exploitabilityScore"] = baseMetricV3.get("exploitabilityScore", "")
        self.cvssv3["impactScore"] = baseMetricV3.get("impactScore", "")

        # GET Dates

        self.publishedDate = data.get("publishedDate", datetime.utcnow())
        self.lastModifiedDate = data.get("lastModifiedDate", datetime.utcnow())

        # Additional fields
        self.component = ""
        self.version = ""

    def to_json(self):
        return json.dumps(self,
                          default=lambda o: o.__dict__,
                          sort_keys=True)