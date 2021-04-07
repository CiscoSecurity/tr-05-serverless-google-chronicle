MODULE_NAME = 'Google Chronicle Conf Token'
PRODUCER = 'Chronicle'
SOURCE_NAME = 'Chronicle IOC'
CONFIDENCE = SEVERITY = ('Low', 'Medium', 'High', 'Info', 'Unknown', 'None')
CTR_ENTITIES_LIMIT = 100
CHRONICLE_LINK = 'https://demodev.backstory.chronicle.security/'
URL_CATEGORY = {
    'ip': 'destinationIpResults',
    'md5': 'hashResults',
    'domain': 'domainResults'
}
RELATION_TYPE = {
    'ip': 'Resolved_To',
    'domain': 'Supra-domain_Of'
}
TARGETS_OBSERVABLES_VALUE = ('pc', 'laptop')
TARGETS_OBSERVABLES_TYPES = ('ip', 'hostname')
