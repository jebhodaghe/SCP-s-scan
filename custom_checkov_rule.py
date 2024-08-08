from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.json_doc.base_json_check import BaseJsonCheck
from checkov.json_doc.registry import registry

class CustomSCPCheck(BaseJsonCheck):
    def __init__(self):
        name = 'Ensure CloudTrail is configured correctly in SCP'
        id = 'CUSTOM_SCP_1'
        supported_entities = ['Statement']
        categories = [CheckCategories.IAM]
        block_type = 'json'
        super().__init__(
            name=name, id=id, categories=categories, supported_entities=supported_entities, block_type=block_type
        )

    def scan_entity_conf(self, conf, entity_type):
        if 'Sid' in conf:
            if conf['Sid'] == 'RequireMultiRegionTrailWithReadAndWriteManagementEvents':
                if not (conf['Condition'].get('StringEquals') and 'cloudtrail:ManagementEventReadWriteType' in conf['Condition']['StringEquals'] and conf['Condition']['StringEquals']['cloudtrail:ManagementEventReadWriteType'] == ["All"]):
                    return CheckResult.FAILED
        return CheckResult.PASSED

registry.register(CustomSCPCheck())
