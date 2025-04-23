#!/usr/bin/env python3
import sys
import argparse
import logging
import json
import datetime
import os
import xml.etree.ElementTree as ET
import traceback
import requests

import anticrlf
from veracode_api_py.api import VeracodeAPI as vapi, Applications, Findings, Sandboxes
from veracode_api_py.constants import Constants
from veracode_api_signing.credentials import get_credentials

log = logging.getLogger(__name__)

ALLOWED_ACTIONS = [
    'COMMENT','FP','APPDESIGN','OSENV','NETENV','REJECTED','ACCEPTED',
    'LIBRARY','ACCEPTRISK','APPROVE','REJECT','BYENV','BYDESIGN',
    'LEGAL','COMMERCIAL','EXPERIMENTAL','INTERNAL','APPROVED'
]

ACTION_MAPPING = {
    "mitigate by design": "APPDESIGN",
    "approve mitigation": "APPROVED",
    "accept risk": "ACCEPTRISK",
    "false positive": "FP",
    "not applicable": "NETENV",
    "comment": "COMMENT",
    "rejected": "REJECTED",
    "accepted": "ACCEPTED",
    "library": "LIBRARY",
    "os environment": "OSENV",
    "network environment": "NETENV",
    "by design": "BYDESIGN",
    "by environment": "BYENV",
    "legal": "LEGAL",
    "commercial": "COMMERCIAL",
    "experimental": "EXPERIMENTAL",
    "internal": "INTERNAL",
    "approve": "APPROVE",
    "reject": "REJECTED"
}


class VeracodeApiCredentials():
    def __init__(self, api_key_id, api_key_secret):
        self.api_key_id = api_key_id
        self.api_key_secret = api_key_secret

    def run_with_credentials(self, fn):
        # Preserve old uppercase environment vars
        old_id = os.environ.get('VERACODE_API_KEY_ID')
        old_secret = os.environ.get('VERACODE_API_KEY_SECRET')
        # Inject new creds
        os.environ['VERACODE_API_KEY_ID'] = self.api_key_id
        os.environ['VERACODE_API_KEY_SECRET'] = self.api_key_secret
        try:
            return fn()
        finally:
            # Restore old values
            if old_id is None:
                os.environ.pop('VERACODE_API_KEY_ID', None)
            else:
                os.environ['VERACODE_API_KEY_ID'] = old_id

            if old_secret is None:
                os.environ.pop('VERACODE_API_KEY_SECRET', None)
            else:
                os.environ['VERACODE_API_KEY_SECRET'] = old_secret


class MitigationData:
    def __init__(self, issue_id, cwe_id, source_file, line_number,
                 source_file_path, mitigation_actions=None,
                 severity=None, flaw_details=None):
        self.issue_id = issue_id
        self.cwe_id = cwe_id
        self.source_file = source_file
        self.line_number = line_number
        self.source_file_path = source_file_path
        self.mitigation_actions = mitigation_actions or []
        self.severity = severity
        self.flaw_details = flaw_details or {}

    def add_mitigation_action(self, action, description, user, date):
        self.mitigation_actions.append({
            'action': action,
            'comment': description,
            'user_name': user,
            'date': date
        })


def setup_logger(debug_mode=False, log_file='MitigationMigrator.log'):
    handler = logging.FileHandler(log_file, encoding='utf8')
    handler.setFormatter(anticrlf.LogFormatter(
        '%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)
    if debug_mode:
        console = logging.StreamHandler()
        console.setFormatter(anticrlf.LogFormatter(
            'DEBUG: %(levelname)s - %(funcName)s - %(message)s'))
        logger.addHandler(console)
    return logger


def logprint(msg):
    log.info(msg)
    print(msg)


def creds_expire_days_warning():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(
        creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    if (exp - datetime.datetime.now().astimezone()).days < 7:
        print(f"Credentials expire soon: {creds['expiration_ts']}")


def parse_xml_detail_report(xml_file_path, debug_mode=False):
    mitigations = []
    try:
        logprint(f"Reading XML: {xml_file_path}")
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        ns = {}
        if root.tag.startswith("{"):
            uri = root.tag.split("}")[0].strip("{")
            ns['ns'] = uri
            flaw_xpath = ".//ns:flaw"
            mitig_xpath = "ns:mitigations"
            m_xpath = "ns:mitigation"
        else:
            flaw_xpath = ".//flaw"
            mitig_xpath = "mitigations"
            m_xpath = "mitigation"

        logprint(f"Namespace map: {ns}" if ns else "No XML namespace")

        flaws = root.findall(flaw_xpath, ns)
        logprint(f"Found {len(flaws)} flaw elements")

        for flaw in flaws:
            status = (flaw.get('mitigation_status') or "").lower()
            if status in ('none', ''):
                continue
            container = flaw.find(mitig_xpath, ns)
            if container is None:
                continue

            md = MitigationData(
                issue_id=flaw.get('issueid'),
                cwe_id=flaw.get('cweid'),
                source_file=flaw.get('sourcefile'),
                line_number=flaw.get('line'),
                source_file_path=flaw.get('sourcefilepath'),
                severity=flaw.get('severity'),
                flaw_details={
                    'categoryname': flaw.get('categoryname'),
                    'type': flaw.get('type'),
                    'description': flaw.get('description'),
                    'module': flaw.get('module'),
                    'scope': flaw.get('scope'),
                    'functionprototype': flaw.get('functionprototype')
                }
            )
            for m in container.findall(m_xpath, ns):
                md.add_mitigation_action(
                    m.get('action'), m.get('description'),
                    m.get('user'), m.get('date')
                )
            mitigations.append(md)

        log.info(f"Extracted {len(mitigations)} mitigations")
        return mitigations

    except Exception as e:
        log.error(f"XML parse error: {e}")
        if debug_mode:
            log.error(traceback.format_exc())
        return []


def map_mitigation_action(xml_action):
    if not xml_action:
        return "COMMENT"
    a = xml_action.lower()
    for k, v in ACTION_MAPPING.items():
        if k in a:
            return v
    return "COMMENT"


def check_flaw_status(app_guid, flaw_id, sandbox_guid=None, debug_mode=False):
    findings = Findings().get_findings(
        app_guid, scantype='STATIC', annot='TRUE', sandbox=sandbox_guid)
    for f in findings:
        if str(f.get('issue_id')) == str(flaw_id):
            status = f['finding_status']['resolution_status']
            if debug_mode:
                log.debug(f"Flaw {flaw_id} status: {status}")
            return status
    return None


def propose_mitigation(app_guid, flaw_id, sandbox_guid=None, debug_mode=False):
    comment = "Proposing mitigation as first step for automated migration"
    Findings().add_annotation(
        app_guid, [flaw_id], comment, "COMMENT",
        sandbox=sandbox_guid or None
    )
    return True


def update_mitigation_info_rest(
    app_guid, flaw_id, action, comment,
    sandbox_guid=None, propose_only=False,
    debug_mode=False, ignore_errors=False
):
    """
    Update mitigation for a flaw. 409 Conflict means 'locked', so skip quietly.
    """
    # Truncate overly long comments
    if len(comment) > 2048:
        comment = comment[:2048]
        if debug_mode:
            log.debug(f"Comment truncated for flaw {flaw_id}")

    if action not in ALLOWED_ACTIONS:
        log.warning(f"Illegal action {action} for flaw {flaw_id}; skipping")
        return True  # treat as success so we don't abort

    # Convert APPROVED to the correct constant if needed
    if action == 'APPROVED':
        action = Constants.ANNOT_TYPE[action]

    # If we need to propose first
    if action == 'APPROVED' and not propose_only:
        status = check_flaw_status(app_guid, flaw_id, sandbox_guid, debug_mode)
        if status != 'PROPOSED':
            if debug_mode:
                log.debug(f"Flaw {flaw_id} not in PROPOSED; proposing first")
            if not propose_mitigation(app_guid, flaw_id, sandbox_guid, debug_mode):
                log.error(f"Failed to propose flaw {flaw_id}; skipping")
                return ignore_errors

    try:
        if debug_mode:
            log.debug(f"Applying {action} to flaw {flaw_id} with comment:\n{comment}")
        Findings().add_annotation(
            app_guid,
            [flaw_id],
            comment,
            action,
            sandbox=sandbox_guid or None
        )
        log.info(f"Applied {action} to flaw {flaw_id}")
        return True

    except requests.exceptions.RequestException as e:
        # If it's a 409 Conflict, the issue is checked-out/locked—skip it
        resp = getattr(e, 'response', None)
        code = getattr(resp, 'status_code', None)
        if code == 409:
            log.warning(f"Flaw {flaw_id} is locked (409 Conflict); skipping annotation")
            return True

        # Otherwise fall through to the generic handler
        log.error(f"RequestException applying {action} to flaw {flaw_id}: {e}")
        if debug_mode and resp is not None:
            try:
                detail = resp.json().get('_embedded', {}).get('api_errors', [])
                for err in detail:
                    log.error(f"  API Error: {err.get('title')} - {err.get('detail')}")
            except Exception:
                pass
        return ignore_errors

    except Exception as e:
        # Any other exception: log and decide based on ignore_errors
        log.error(f"Unexpected error applying {action} to flaw {flaw_id}: {e}")
        if debug_mode:
            log.error(traceback.format_exc())
        return ignore_errors

def format_file_path(file_path):
    # same as you had before
    if not file_path:
        return ''
    idx = file_path.find('teamcity/buildagent/work/')
    return file_path[(idx + 42):] if idx > 0 else file_path

def find_matching_flaws(app_guid, mitigation_data_list, sandbox_guid=None, fuzzy_match=False, debug_mode=False):
    """
    Find matching flaws in the target app based on CWE ID, file path, and line number.
    This version logs every step for debugging.
    """
    matches = {}
    findings = Findings().get_findings(app_guid, scantype='STATIC', annot='TRUE', sandbox=sandbox_guid)
    logprint(f"Retrieved {len(findings)} findings from target")
    if debug_mode:
        findings = Findings().get_findings(app_guid,scantype='STATIC', annot='TRUE',)
        filtered = [f for f in findings if str(f.get('issue_id')) == '1']
        print(json.dumps(filtered, indent=2))

    for md in mitigation_data_list:
       
        if debug_mode:
            log.debug(f"--- Looking for matches for XML flaw {md.issue_id} (CWE={md.cwe_id}, File={md.source_file}, Path={md.source_file_path}, Line={md.line_number})")

        for f in findings:
            status = f['finding_status']['resolution_status']
            if status == 'APPROVED':
                if debug_mode:
                    log.debug(f"  Skipping finding {f['issue_id']} because status={status}")
                continue

            # 1) CWE match
            finding_cwe = f['finding_details']['cwe']['id']
            if int(finding_cwe) != int(md.cwe_id):
                #if debug_mode:
                 #log.debug(f"  CWE mismatch: finding {finding_cwe} vs {md.cwe_id}")
                #continue
                continue

            # 2) File name match
            finding_file = f['finding_details'].get('file_name','').strip().lower()
            xml_file = md.source_file.strip().lower()
            if xml_file != finding_file:
                if debug_mode:
                    log.debug(f"  File name mismatch: finding '{finding_file}' vs xml '{xml_file}'")
                continue

            # 3) Path match (if you have it)
            xml_path = (md.source_file_path or '').replace('\\','/').strip().lower()
            find_path = format_file_path(f['finding_details'].get('file_path','')).replace('\\','/').strip().lower()
            if xml_path and find_path and xml_path not in find_path and find_path not in xml_path:
                if debug_mode:
                    log.debug(f"  Path mismatch: finding '{find_path}' vs xml '{xml_path}'")
                continue

            # 4) Line number match
            finding_line = f['finding_details'].get('file_line_number')
            if md.line_number and finding_line:
                try:
                    md_line = int(md.line_number)
                    fg_line = int(finding_line)
                except ValueError:
                    if debug_mode:
                        log.debug("  Line number not integer, skipping line check")
                else:
                    if fuzzy_match:
                        if abs(fg_line - md_line) > 5:
                            if debug_mode:
                                log.debug(f"  Line mismatch (fuzzy): finding {fg_line} vs xml {md_line}")
                            continue
                    else:
                        if fg_line != md_line:
                            if debug_mode:
                                log.debug(f"  Line mismatch: finding {fg_line} vs xml {md_line}")
                            continue

            # if we get here, everything matched
            if debug_mode:
                log.debug(f"  → MATCH FOUND: flawID {f['issue_id']}")
            matches[md] = f
            break

    return matches

def get_exact_application_by_name(app_name, debug_mode=False):
    """
    Return the GUID of the application whose profile.name exactly matches app_name.
    If multiple candidates match partially (get_by_name returns >1), prompt the user
    to pick one.
    """
    candidates = Applications().get_by_name(app_name)
    if debug_mode:
        log.debug(f"DEBUG: Found {len(candidates)} candidate apps for '{app_name}':")
        for idx, a in enumerate(candidates, 1):
            log.debug(f"  {idx}) {a['profile']['name']} (guid: {a['guid']})")

    # First try an exact match on profile.name
    for a in candidates:
        if a['profile']['name'] == app_name:
            return a['guid']

    # No exact match—if only one candidate, just return it
    if len(candidates) == 1:
        return candidates[0]['guid']

    # Multiple partial matches—prompt user
    print(f"\nMultiple applications match '{app_name}'. Please choose one:")
    for idx, a in enumerate(candidates, 1):
        print(f"  {idx}) {a['profile']['name']} (guid: {a['guid']})")

    while True:
        choice = input(f"Enter number [1–{len(candidates)}], or 'q' to quit: ").strip()
        if choice.lower() == 'q':
            sys.exit("Exiting per user request.")
        if not choice.isdigit():
            print("Please enter a valid number.")
            continue
        i = int(choice)
        if 1 <= i <= len(candidates):
            return candidates[i-1]['guid']
        print("Number out of range; try again.")




def apply_mitigations(
    app_guid,
    matches,
    sandbox_guid=None,
    dry_run=False,
    propose_only=False,
    debug_mode=False
):
    """
    For each matched flaw:
      1) Sort mitigation_actions by date ascending
      2) Loop in that order; map XML->API action
      3) If propose_only and action is APPROVE/REJECT, skip it
      4) Annotate each in turn with the same "one‑shot" comment
    """
    successes = 0

    for md, finding in matches.items():
        flaw_id = finding['issue_id']
        logprint(f"=== Flaw {flaw_id}: ordered annotations ===")

        # Build the single comment once
        first = md.mitigation_actions[0]
        dt = datetime.datetime.strptime(first['date'], "%Y-%m-%d %H:%M:%S %Z")
        comment = "\n".join([
            f"Original submitter: {first['user_name']}",
            f"Original submission time: {dt.strftime('%m/%d/%Y - %H:%M:%S')}",
            "",
            "Action body:",
            f"\"{first['comment']}\""
        ])

        # Sort actions by their 'date' field
        try:
            ordered_actions = sorted(
                md.mitigation_actions,
                key=lambda a: datetime.datetime.strptime(a['date'], "%Y-%m-%d %H:%M:%S %Z")
            )
        except Exception:
            # Fallback to original order if parsing fails
            ordered_actions = md.mitigation_actions[:]

        for idx, act in enumerate(ordered_actions, 1):
            dt = datetime.datetime.strptime(act['date'], "%Y-%m-%d %H:%M:%S %Z")
            comment = "\n".join([
                f"Original submitter: {act['user_name']}",
                f"Original submission time: {dt.strftime('%m/%d/%Y - %H:%M:%S')}",
                "",
                "Action body:",
                f"\"{act['comment']}\""
])
            xml_action = act['action']
            api_action = map_mitigation_action(xml_action)

            # Skip approv/reject if propose_only is set
            if propose_only and api_action in ('APPROVED', 'REJECT'):
                if debug_mode:
                    log.debug(f"  Skipping {api_action} (propose_only): {xml_action}")
                continue

            logprint(f"  [{idx}/{len(ordered_actions)}] Applying {api_action} for XML action \"{xml_action}\"")

            if dry_run:
                # Simulate without calling API
                continue

            # Perform the real annotation
            success = update_mitigation_info_rest(
                app_guid,
                flaw_id,
                api_action,
                comment,
                sandbox_guid,
                propose_only,
                debug_mode
            )

            if not success:
                log.error(f"  Failed to apply {api_action} on {flaw_id}")
                break
        else:
            # Only count as success if we completed the loop without break
            successes += 1

    return successes


def prompt_for_app(prompt_text):
    name = input(prompt_text)
    apps = Applications().get_by_name(name)
    if not apps:
        print("No app found")
        return None
    if len(apps) > 1:
        for i, a in enumerate(apps, 1):
            print(f"{i}) {a['profile']['name']}")
        sel = int(input("Choose number: "))
        return apps[sel-1]['guid']
    return apps[0]['guid']


def main():
    parser = argparse.ArgumentParser(
        description="Migrate Veracode XML mitigations into a target app"
    )
    parser.add_argument('-x','--xml_report',    required=True)
    parser.add_argument('-t','--toapp',          help="Target app GUID")
    parser.add_argument('-tn','--toappname',     help="Target app name")
    parser.add_argument('-tsn','--tosandboxname',help="Sandbox name")
    parser.add_argument('-d','--dry_run',        action='store_true')
    parser.add_argument('-fm','--fuzzy_match',   action='store_true')
    parser.add_argument('-po','--propose_only',  action='store_true')
    parser.add_argument('-vid','--veracode_api_key_id')
    parser.add_argument('-vkey','--veracode_api_key_secret')
    parser.add_argument('-p','--prompt',         action='store_true',
                        help="Interactive app selection")
    parser.add_argument('--debug',               action='store_true')
    args = parser.parse_args()

    global log
    log = setup_logger(debug_mode=args.debug)

    logprint("=== Start run ===")

    # Initialize credentials wrapper
    if args.veracode_api_key_id and args.veracode_api_key_secret:
        creds = VeracodeApiCredentials(
            args.veracode_api_key_id, args.veracode_api_key_secret
        )
    else:
        kid, ksec = get_credentials()
        creds = VeracodeApiCredentials(kid, ksec)

    # Check expiration under new creds
    creds.run_with_credentials(creds_expire_days_warning)

    # Parse XML (no creds needed)
    md_list = parse_xml_detail_report(args.xml_report, debug_mode=args.debug)
    if not md_list:
        logprint("No mitigations found – exiting.")
        return

    # Determine application GUID
    app_guid = args.toapp
    if not app_guid and args.toappname:
        app_guid = creds.run_with_credentials(
        lambda: get_exact_application_by_name(args.toappname, args.debug)
    )
    if not app_guid:
        log.error(f"No application found with exact name '{args.toappname}'.")
        sys.exit(1)
    elif not app_guid and args.prompt:
        app_guid = creds.run_with_credentials(
            lambda: prompt_for_app("App name: ")
        )
    if not app_guid:
       log.error("No target app provided; use --toapp or --toappname.")
       sys.exit(1)

    # Optional sandbox lookup under new creds
    sandbox_guid = None
    if args.tosandboxname:
        sandbox_list = creds.run_with_credentials(
            lambda: Sandboxes().get_all(app_guid)
        )
        sandbox_guid = next(
            (s['guid'] for s in sandbox_list if s['name']==args.tosandboxname),
            None
        )
        if not sandbox_guid:
            log.error(f"Sandbox not found: {args.tosandboxname}")
            sys.exit(1)

    # Find matching flaws under new creds
    matches = creds.run_with_credentials(
        lambda: find_matching_flaws(
            app_guid, md_list, sandbox_guid,
            args.fuzzy_match, args.debug
        )
    )
    if not matches:
        logprint("No matching flaws – exiting.")
        return

    # Apply mitigations under new creds
    updated = creds.run_with_credentials(
        lambda: apply_mitigations(
            app_guid, matches, sandbox_guid,
            args.dry_run, args.propose_only, args.debug
        )
    )
    logprint(f"=== Completed: {updated}/{len(matches)} flaws updated ===")


if __name__ == '__main__':
    main()
