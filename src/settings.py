import logging
import os
from typing import Optional, List
from env_vars import get_required_env_var, get_env_var_bool, get_env_var_list

logger = logging.getLogger(__name__)

class Settings:
    LABEL: Optional[str] = os.getenv("LABEL")
    LABEL_VALUE: Optional[str] = os.getenv("LABEL_VALUE")

    DEFECT_DOJO_API_KEY: str = get_required_env_var("DEFECT_DOJO_API_KEY")
    DEFECT_DOJO_URL: str = get_required_env_var("DEFECT_DOJO_URL").rstrip("/")

    DEFECT_DOJO_ACTIVE: bool = get_env_var_bool("DEFECT_DOJO_ACTIVE")
    DEFECT_DOJO_VERIFIED: bool = get_env_var_bool("DEFECT_DOJO_VERIFIED")
    DEFECT_DOJO_CLOSE_OLD_FINDINGS: bool = get_env_var_bool("DEFECT_DOJO_CLOSE_OLD_FINDINGS")
    DEFECT_DOJO_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE: bool = get_env_var_bool(
        "DEFECT_DOJO_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE"
    )
    DEFECT_DOJO_PUSH_TO_JIRA: bool = get_env_var_bool("DEFECT_DOJO_PUSH_TO_JIRA")
    DEFECT_DOJO_MINIMUM_SEVERITY: str = os.getenv("DEFECT_DOJO_MINIMUM_SEVERITY", "Info")
    DEFECT_DOJO_AUTO_CREATE_CONTEXT: bool = get_env_var_bool("DEFECT_DOJO_AUTO_CREATE_CONTEXT")
    DEFECT_DOJO_DEDUPLICATION_ON_ENGAGEMENT: bool = get_env_var_bool(
        "DEFECT_DOJO_DEDUPLICATION_ON_ENGAGEMENT"
    )
    DEFECT_DOJO_DO_NOT_REACTIVATE: bool = get_env_var_bool("DEFECT_DOJO_DO_NOT_REACTIVATE")

    DEFECT_DOJO_PRODUCT_TYPE_NAME: str = os.getenv("DEFECT_DOJO_PRODUCT_TYPE_NAME", "")
    DEFECT_DOJO_EVAL_PRODUCT_TYPE_NAME: bool = get_env_var_bool("DEFECT_DOJO_EVAL_PRODUCT_TYPE_NAME")

    DEFECT_DOJO_SERVICE_NAME: str = os.getenv("DEFECT_DOJO_SERVICE_NAME", "")
    DEFECT_DOJO_EVAL_SERVICE_NAME: bool = get_env_var_bool("DEFECT_DOJO_EVAL_SERVICE_NAME")

    DEFECT_DOJO_ENV_NAME: str = os.getenv("DEFECT_DOJO_ENV_NAME", "Development")
    DEFECT_DOJO_EVAL_ENV_NAME: bool = get_env_var_bool("DEFECT_DOJO_EVAL_ENV_NAME")

    DEFECT_DOJO_TEST_TITLE: str = os.getenv("DEFECT_DOJO_TEST_TITLE", "Kubernetes")
    DEFECT_DOJO_EVAL_TEST_TITLE: bool = get_env_var_bool("DEFECT_DOJO_EVAL_TEST_TITLE")

    DEFECT_DOJO_ENGAGEMENT_NAME: Optional[str] = os.getenv("DEFECT_DOJO_ENGAGEMENT_NAME")
    DEFECT_DOJO_EVAL_ENGAGEMENT_NAME: bool = get_env_var_bool("DEFECT_DOJO_EVAL_ENGAGEMENT_NAME")

    DEFECT_DOJO_PRODUCT_NAME: str = os.getenv("DEFECT_DOJO_PRODUCT_NAME", "product")
    DEFECT_DOJO_EVAL_PRODUCT_NAME: bool = get_env_var_bool("DEFECT_DOJO_EVAL_PRODUCT_NAME")

    DEFECT_DOJO_EVAL_TAGS: bool = get_env_var_bool("DEFECT_DOJO_EVAL_TAGS")
    DEFECT_DOJO_TAGS: List[str] = get_env_var_list("DEFECT_DOJO_TAGS")

    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
    REPORTS: List[str] = get_env_var_list("REPORTS", ["vulnerabilityreports"])

    HTTP_PROXY: Optional[str] = os.getenv("HTTP_PROXY") or os.getenv("http_proxy")
    HTTPS_PROXY: Optional[str] = os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")

    @classmethod
    def log_config(cls) -> None:
        if cls.LABEL and cls.LABEL_VALUE:
            logger.info(f"Filtering resources with label '{cls.LABEL}={cls.LABEL_VALUE}'")
        elif cls.LABEL:
            logger.info(f"Filtering resources with label '{cls.LABEL}'")
        else:
            logger.info("Processing all resources")

        logger.info(f"DefectDojo URL: {cls.DEFECT_DOJO_URL}")
        logger.info(f"Reports to process: {cls.REPORTS}")

Settings.log_config()
