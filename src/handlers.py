import json
import logging
from io import BytesIO
from typing import Dict, List, Any
import requests
from requests.exceptions import HTTPError, RequestException
import kopf
import prometheus_client as prometheus

import settings

logger = logging.getLogger(__name__)

prometheus.start_http_server(9090)
REQUEST_TIME = prometheus.Summary(
    "request_processing_seconds", "Time spent processing request"
)
REQUESTS_TOTAL = prometheus.Counter(
    "requests_total", "Total HTTP Requests", ["status"]
)

proxies = {
    "http": settings.Settings.HTTP_PROXY,
    "https": settings.Settings.HTTPS_PROXY,
} if settings.Settings.HTTP_PROXY or settings.Settings.HTTPS_PROXY else None

ALLOWED_REPORTS: List[str] = [
    "configauditreports",
    "vulnerabilityreports",
    "exposedsecretreports",
    "infraassessmentreports",
    "rbacassessmentreports",
]

def validate_reports(reports: List[str]) -> None:
    for report in reports:
        if report not in ALLOWED_REPORTS:
            logger.error(
                f"Invalid report type: {report}. Allowed reports: {', '.join(ALLOWED_REPORTS)}"
            )
            raise SystemExit(1)

@kopf.on.probe(id="health")
def health_check(**kwargs) -> str:
    return "ok"

@kopf.on.startup()
def configure_kopf(settings: kopf.OperatorSettings, **_) -> None:
    settings.watching.connect_timeout = 60
    settings.watching.server_timeout = 600
    settings.watching.client_timeout = 610

    settings.persistence.diffbase_storage = kopf.MultiDiffBaseStorage(
        [kopf.StatusDiffBaseStorage(field="status.diff-base")]
    )

def evaluate_setting(value: str, context: Dict[str, Any], default: str = "") -> str:
    try:
        return str(eval(value, {}, context)) if value else default
    except Exception as e:
        logger.error(f"Error evaluating setting '{value}': {e}")
        return default

def prepare_dojo_data(body: Dict, meta: Dict) -> Dict:
    context = {"meta": meta, "body": body}

    tags = []
    if settings.Settings.DEFECT_DOJO_EVAL_TAGS:
        for tag in settings.Settings.DEFECT_DOJO_TAGS:
            evaluated_tag = evaluate_setting(tag, context)
            if evaluated_tag:
                tags.append(evaluated_tag)

    return {
        "active": settings.Settings.DEFECT_DOJO_ACTIVE,
        "verified": settings.Settings.DEFECT_DOJO_VERIFIED,
        "close_old_findings": settings.Settings.DEFECT_DOJO_CLOSE_OLD_FINDINGS,
        "close_old_findings_product_scope": settings.Settings.DEFECT_DOJO_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE,
        "push_to_jira": settings.Settings.DEFECT_DOJO_PUSH_TO_JIRA,
        "minimum_severity": settings.Settings.DEFECT_DOJO_MINIMUM_SEVERITY,
        "auto_create_context": settings.Settings.DEFECT_DOJO_AUTO_CREATE_CONTEXT,
        "deduplication_on_engagement": settings.Settings.DEFECT_DOJO_DEDUPLICATION_ON_ENGAGEMENT,
        "scan_type": "Trivy Operator Scan",
        "engagement_name": evaluate_setting(
            settings.Settings.DEFECT_DOJO_ENGAGEMENT_NAME,
            context,
            settings.Settings.DEFECT_DOJO_ENGAGEMENT_NAME or ""
        ) if settings.Settings.DEFECT_DOJO_EVAL_ENGAGEMENT_NAME else settings.Settings.DEFECT_DOJO_ENGAGEMENT_NAME or "",
        "product_name": evaluate_setting(
            settings.Settings.DEFECT_DOJO_PRODUCT_NAME,
            context,
            settings.Settings.DEFECT_DOJO_PRODUCT_NAME
        ) if settings.Settings.DEFECT_DOJO_EVAL_PRODUCT_NAME else settings.Settings.DEFECT_DOJO_PRODUCT_NAME,
        "product_type_name": evaluate_setting(
            settings.Settings.DEFECT_DOJO_PRODUCT_TYPE_NAME,
            context,
            settings.Settings.DEFECT_DOJO_PRODUCT_TYPE_NAME
        ) if settings.Settings.DEFECT_DOJO_EVAL_PRODUCT_TYPE_NAME else settings.Settings.DEFECT_DOJO_PRODUCT_TYPE_NAME,
        "service": evaluate_setting(
            settings.Settings.DEFECT_DOJO_SERVICE_NAME,
            context,
            settings.Settings.DEFECT_DOJO_SERVICE_NAME
        ) if settings.Settings.DEFECT_DOJO_EVAL_SERVICE_NAME else settings.Settings.DEFECT_DOJO_SERVICE_NAME,
        "environment": evaluate_setting(
            settings.Settings.DEFECT_DOJO_ENV_NAME,
            context,
            settings.Settings.DEFECT_DOJO_ENV_NAME
        ) if settings.Settings.DEFECT_DOJO_EVAL_ENV_NAME else settings.Settings.DEFECT_DOJO_ENV_NAME,
        "test_title": evaluate_setting(
            settings.Settings.DEFECT_DOJO_TEST_TITLE,
            context,
            settings.Settings.DEFECT_DOJO_TEST_TITLE
        ) if settings.Settings.DEFECT_DOJO_EVAL_TEST_TITLE else settings.Settings.DEFECT_DOJO_TEST_TITLE,
        "do_not_reactivate": settings.Settings.DEFECT_DOJO_DO_NOT_REACTIVATE,
        "tags": tags,
        ## !TODO: make it optional to enable/disable jira
        "push_to_jira": True,
        "active": True,
        "verified": True,
    }

@REQUEST_TIME.time()
def send_to_dojo(body: Dict, meta: Dict[str, str], logger: Any, **_) -> None:
    logger.info(f"Processing {body['kind']} {meta['name']}")

    report_data = dict(body)
    logger.debug(json.dumps(report_data, indent=2))

    json_string = json.dumps(report_data)
    json_file = BytesIO(json_string.encode("utf-8"))
    files = {"file": ("report.json", json_file)}

    headers = {
        "Authorization": f"Token {settings.Settings.DEFECT_DOJO_API_KEY}",
        "Accept": "application/json",
    }

    data = prepare_dojo_data(body, meta)

    try:
        ## !TODO:
        ## this is not efficient to go through all jira_projects for each re-import
        ## move to somewhere else in the code logic
        response = requests.post(
            f"{settings.Settings.DEFECT_DOJO_URL}/api/v2/reimport-scan/",
            headers=headers,
            data=data,
            files=files,
            verify=True,
            proxies=proxies,
            timeout=5,
        )
        response.raise_for_status()

        response_json = response.json()
        patch_response = requests.patch(
            f"{settings.Settings.DEFECT_DOJO_URL}/api/v2/products/{response_json['product_id']}/",
            headers=headers,
            json={"tags": data["tags"]},
            verify=True,
            proxies=proxies,
            timeout=5,
        )
        patch_response.raise_for_status()

        get_jira_projects_response = requests.get(
            f"{settings.Settings.DEFECT_DOJO_URL}/api/v2/jira_projects/",
            headers=headers,
            verify=True,
            proxies=proxies,
            timeout=5,
        )
        get_jira_projects_response.raise_for_status()
        jp_response_json = get_jira_projects_response.json()
        found_jp = False
        for proj in jp_response_json["results"]:
          if proj["product"] == response_json["product_id"]:
            logger.info(f"jira project found for {response_json['product_id']} -- skipping")
            found_jp = True
            break
        if not found_jp:
          jira_project_creation_response = requests.post(
            f"{settings.Settings.DEFECT_DOJO_URL}/api/v2/jira_projects/",
            headers=headers,
            json={
              "project_key": f"{settings.Settings.DEFECT_DOJO_JIRA_KEY}",
              ## TODO: since we are going to use just one jira integration, it can be set to a single value
              "jira_instance": int(settings.Settings.DEFECT_DOJO_JIRA_INSTANCE_ID),
              "product": f"{response_json['product_id']}",
            },
            verify=True,
            proxies=proxies,
            timeout=5,
          )
          jira_project_creation_response.raise_for_status()

        REQUESTS_TOTAL.labels("success").inc()
        logger.info(f"Successfully processed {body['kind']} {meta['name']}")
        logger.debug(f"Response: {response.content}")

    except HTTPError as http_err:
        REQUESTS_TOTAL.labels("failed").inc()
        error_response = http_err.response
        error_content = error_response.content if error_response else "No response"
        logger.error(f"HTTP error: {http_err}, Response: {error_content}")
        raise kopf.TemporaryError(f"HTTP error: {http_err}", delay=60)
    except RequestException as req_err:
        REQUESTS_TOTAL.labels("failed").inc()
        logger.error(f"Request error: {req_err}")
        raise kopf.TemporaryError(f"Request error: {req_err}", delay=60)
    except Exception as err:
        REQUESTS_TOTAL.labels("failed").inc()
        logger.error(f"Unexpected error: {err}")
        raise kopf.TemporaryError(f"Unexpected error: {err}", delay=60)

labels = {settings.Settings.LABEL: settings.Settings.LABEL_VALUE} if settings.Settings.LABEL and settings.Settings.LABEL_VALUE else {}
validate_reports(settings.Settings.REPORTS)

for report in settings.Settings.REPORTS:
    kopf.on.create(f"{report.lower()}.aquasecurity.github.io", labels=labels)(send_to_dojo)
