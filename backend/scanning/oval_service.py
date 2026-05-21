import os
import re
import xml.etree.ElementTree as ET
from django.utils import timezone
from .models import Vulnerability
from .cve_models import CVEData

class OVALEvaluator:
    def __init__(self, scan):
        self.scan = scan

    def parse_oval(self, xml_path):
        result = []
        if not xml_path or not os.path.exists(xml_path):
            return result
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ns = {'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5'}
        for d in root.findall('.//oval:definition', ns):
            def_id = d.get('id') or ''
            title_el = d.find('./oval:metadata/oval:title', ns)
            title = title_el.text if title_el is not None else def_id
            refs = []
            for r in d.findall('./oval:metadata/oval:reference', ns):
                ref_id = r.get('ref_id') or ''
                if ref_id:
                    refs.append(ref_id)
            crit_items = []
            for c in d.findall('.//oval:criterion', ns):
                comment = c.get('comment') or ''
                crit_items.append(comment)
            result.append({
                'id': def_id,
                'title': title,
                'references': refs,
                'criteria': crit_items
            })
        return result

    def _version_tuple(self, v):
        parts = re.split(r'[^0-9a-zA-Z]+', v)
        cleaned = []
        for p in parts:
            if p == '':
                continue
            if p.isdigit():
                cleaned.append(int(p))
            else:
                cleaned.append(p)
        return tuple(cleaned)

    def _compare_versions(self, v1, op, v2):
        t1 = self._version_tuple(v1)
        t2 = self._version_tuple(v2)
        if op == 'earlier' or op == 'less':
            return t1 < t2
        if op == 'later' or op == 'greater':
            return t1 > t2
        if op == 'equal':
            return t1 == t2
        return False

    def evaluate(self, host_inventory, definitions):
        matches = []
        pkgs = host_inventory.get('packages') or []
        pkg_map = {p.get('name', '').lower(): p.get('version', '') for p in pkgs}
        os_info = host_inventory.get('os') or {}
        for d in definitions:
            defs_true = True
            evidence = []
            for comment in d.get('criteria', []):
                m = re.search(r'package\s+([A-Za-z0-9._+-]+)\s+is\s+(earlier|less|later|greater|equal)\s+than\s+([A-Za-z0-9._:+-]+)', comment, re.IGNORECASE)
                if m:
                    name = m.group(1).lower()
                    op = m.group(2).lower()
                    ver = m.group(3)
                    cur = pkg_map.get(name)
                    ok = bool(cur) and self._compare_versions(cur, op, ver)
                    evidence.append({'package': name, 'current_version': cur or '', 'operator': op, 'version': ver, 'match': ok})
                    if not ok:
                        defs_true = False
                else:
                    evidence.append({'note': comment})
            if defs_true:
                matches.append({'definition': d, 'evidence': evidence, 'os': os_info})
        return matches

    def create_vulnerabilities(self, matches):
        created = 0
        for m in matches:
            d = m['definition']
            title = f"OVAL: {d.get('title')}"
            refs = d.get('references') or []
            cve_id = None
            cvss_score = None
            severity = 'medium'
            if refs:
                for r in refs:
                    if r.upper().startswith('CVE-'):
                        cve_id = r
                        break
            if cve_id:
                cve = CVEData.objects.filter(cve_id=cve_id).first()
                if cve and (cve.cvss_v3_score or cve.cvss_v31_score or cve.cvss_v2_score):
                    cvss_score = cve.cvss_v3_score or cve.cvss_v31_score or cve.cvss_v2_score
                    if cvss_score >= 9.0:
                        severity = 'critical'
                    elif cvss_score >= 7.0:
                        severity = 'high'
                    elif cvss_score >= 4.0:
                        severity = 'medium'
                    else:
                        severity = 'low'
            loc = ''
            os_info = m.get('os') or {}
            if os_info:
                loc = f"{os_info.get('name','')}-{os_info.get('version','')}".strip('-')
            evidence = {
                'oval_definition_id': d.get('id'),
                'criteria': m.get('evidence'),
            }
            rec = 'Update affected packages to a non-vulnerable version.'
            vuln = Vulnerability.objects.create(
                scan=self.scan,
                title=title,
                description='Host matches OVAL vulnerability criteria.',
                severity=severity,
                cve_id=cve_id,
                cvss_score=cvss_score,
                location=loc or (self.scan.target.target_url if self.scan.target else ''),
                evidence=evidence,
                recommendation=rec,
                vulnerability_type='OVAL Compliance',
                affected_component='',
                remediation_steps=['Upgrade affected package to fixed version']
            )
            created += 1
        return created
