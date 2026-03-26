import logging
import requests
import time
import json 
import subprocess
from datetime import datetime, timezone
from typing import Any, List, Dict, Union

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)
architectures = ["linux/amd64","linux/arm64/v8","linux/s390x","linux/ppc64le"]

def get_image_digest_id(pull_spec: str, arch: str) -> Optional[str]:
    """
    Returns the image digestID for a specific architecture using OpenShift CLI.
    """
    command = [
        "oc", "image", "info", 
        pull_spec, 
        "--filter-by-os", arch, 
        "-o", "json"
    ]
    logger.debug(f"command={command}")
    try:
        # Run the command
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Convert string output to Python object
        data = json.loads(result.stdout)
        return data.get('digest')

    except subprocess.CalledProcessError as e:
        # e.stderr contains the actual error from the 'oc' command
        logger.warning(f"CLI Error: {e.stderr.strip()}")
        return None
    except (json.JSONDecodeError, AttributeError) as e:
        logger.warning(f"Data Parsing Error: {e}")
        return None
    except FileNotFoundError:
        logger.warning("Error: 'oc' binary not found in PATH.")
        return None

def query_pyxis_freshness( image_digest: str) -> tuple[list[dict], str]:
    logger.debug(f"query_pyxis_freshness")
    """Query Pyxis container registry API for image freshness grades.

    Args:
        image_digest: SHA256 image digest to query (with "sha256:" prefix)

    Returns:
        tuple[list[dict], str]: Freshness grade objects and vulnerabilities href

    Raises:
        ShipmentDataException: If API request fails or returns invalid response

    Note:
        Uses corporate proxy (squid.corp.redhat.com:3128) for the request
    """
    try:
        url = f"https://catalog.stage.redhat.com/api/containers/v1/images?filter=image_id=={image_digest}&page_size=100&page=0"
        proxies = {"https": "squid.corp.redhat.com:3128"}

        response = requests.get(url, proxies=proxies, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        if not data.get("data"):
            return [], ""
        image_data = data["data"][0]
        grades = image_data.get("freshness_grades", [])
        vuln_href = image_data.get("_links", {}).get("vulnerabilities", {}).get("href", "")
        return grades, vuln_href
    except Exception as e:
        ##raise ShipmentDataException(f"Failed to query Pyxis API: {e}") from e
        logger.warning(f"Failed to fetch vulnerabilities for {image_name}: {str(e)}")

def get_current_image_health_status(grades: list[dict]) -> str:
    logger.debug(f"get_current_image_health_status")
    """Determine the current health status from Pyxis freshness grades.

    Args:
        grades: List of freshness grade dictionaries from Pyxis API,
               each containing start_date and grade fields

    Returns:
        str: Current health status grade (A, B, C, etc.) or "Unknown" if:
             - No grades provided
             - No valid grades found (start_date <= current time)

    Note:
        Selects the most recent valid grade (newest start_date before now)
    """

    if not grades:
        return "Unknown"

    now = datetime.now(timezone.utc)
    # Get all grades that started before now and sort by start_date (newest first)
    valid_grades = sorted(
        [g for g in grades if datetime.fromisoformat(g["start_date"]) <= now],
        key=lambda g: datetime.fromisoformat(g["start_date"]),
        reverse=True
    )

    if not valid_grades:
        return "Unknown"

    # Return the most recent grade (first in the sorted list)
    return valid_grades[0].get("grade", "Unknown")


def query_pyxis_vulnerabilities(vuln_href: str) -> list[dict]:
    logger.debug(f"query_pyxis_vulnerabilities")
    """Query Pyxis API for image vulnerability details.

    Args:
        vuln_href: Relative vulnerabilities href from the images API response
                       (e.g. "/v1/images/id/<id>/vulnerabilities")

    Returns:
        list[dict]: List of vulnerability objects, each containing cve_id, severity,
                    affected_packages (current vulnerable packages), and packages
                    (fixed/suggested source RPMs)

    Raises:
        ShipmentDataException: If API request fails or returns invalid response

    Note:
        Uses corporate proxy (squid.corp.redhat.com:3128) for the request
    """
    try:
        url = f"https://catalog.stage.redhat.com/api/containers{vuln_href}?page_size=100&page=0"
        proxies = {"https": "squid.corp.redhat.com:3128"}

        response = requests.get(url, proxies=proxies, timeout=30)
        response.raise_for_status()

        data = response.json()
        return data.get("data", [])
    except Exception as e:
        raise ShipmentDataException(f"Failed to query Pyxis vulnerabilities API: {e}") from e

def get_image_name(pull_spec: str) -> str:
    return pull_spec.split('@')[0].split('/')[-1]

def main():
   images  = ["registry.stage.redhat.io/xxx/yyy"]
   total_scanned = 0
   healthy_image_names = []
   unhealthy_image_names = []

   for pull_spec in images:
       logger.debug(f"image = {pull_spec}")
       image_name = get_image_name(pull_spec)
       try:
           for arch in architectures:
               digest = get_image_digest_id(pull_spec,arch)
               grades, vuln_href = query_pyxis_freshness(digest)
               grade = get_current_image_health_status(grades)
               logger.info(f" {image_name} {arch} health grade: {grade}")

               total_scanned += 1
               if grade and (grade == "Unknown" or grade > "B"):
                   vulnerabilities = []
                   if vuln_href:
                       try:
                           vulnerabilities = query_pyxis_vulnerabilities(vuln_href)
                       except Exception as e:
                           logger.warning(f"Failed to fetch vulnerabilities for {image_name} {arch}: {str(e)}")
                       logger.debug(f" {image_name} {arch} health grade: {grade}")
                       unhealthy_image_names.append({
                           "name": image_name,
                           "grade": grade,
                           "pull_spec": pull_spec,
                           "architecture": arch,
                           "vulnerabilities": vulnerabilities,
                       })
               else:
                   healthy_image_names.append({
                       "name": image_name,
                       "grade": grade,
                       "pull_spec": pull_spec,
                       "architecture": arch
                   })

       except Exception as e:
           logger.warning(f"Failed to check freshness for image: {str(e)}")
           continue

       print("==== Health Images grade ====")
       for item in healthy_image_names:
           print(f"{item['grade']} --> {item['name']}:{item['architecture']}")

       print("==== Unhealth Images grade ====")
       for item in unhealthy_image_names:
           print(f"{item['grade']} --> {item['name']}:{item['architecture']}")
           #print(f"{item['grade']} --> {item['name']}:{item['architecture']} {item['vulnerabilities']}")


# This check prevents code from running automatically during imports
if __name__ == "__main__":
    main()

