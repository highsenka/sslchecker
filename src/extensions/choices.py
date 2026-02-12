from enum import Enum


class Environment(str, Enum):
    """Окружение, в котором запущено приложение"""

    DEV = "DEV"
    TEST = "TEST"
    PROD = "PROD"
    LOCAL = "LOCAL"



class KeyType(str, Enum):
    """Key types"""
    
    RSA = "RSA"
    EC = "EC"
    NONE = "None"
    
class CertificateTemplate(str, Enum):
    """Шоблон сертификата"""
    
    DOMAIN = "Domain"
    MULTI = "Multi"
    WILDCARD = "Wildcard"
    ROOT = "Root"
    INTERMEDIATE = "Intermediate"
    WEBSERVER = "Webserver"
    WEBSERVER_WITH_CLIENT_AUTH = "Webserver with client authentication"
    
class CertificateState(str, Enum):
    """Статус сертификата"""
    
    ACTIVE = "Active"
    EXPIRED = "Expired"
    REVOKED = "Revoked"
    RESERVED = "Reserved"
    PENDING = "Pending"
    RESTRICTED = "Restricted"

class CertificateRenewState(str, Enum):
    """Статус обновления сертификата"""
    
    REISSUED = "Reissued"
    RENEW = "Renew"
    CANCELED = "Canceled"


class TokenState(str, Enum):
    ACTIVE = "Active"
    DISABLEB = "Disabled"
    RESTRICTED = "Restricted"
    EXPIRED = "Expired"
    REVOKED = "Revoked"
    

class OrderState(str, Enum):
    """Статус заказа"""
    
    NEW = "New"
    INITIALIZED = "Initialized"
    WAITING_APPROVAL = "Waiting approval"
    APPROVED = "Approved"
    IN_PROGRESS = "In progress"
    COMPLETED = "Completed"
    DECLINED = "Declined"


class OrderStateIn(str, Enum):
    """Варианты статуса заказа для фильтрации из API"""
    NEW = "New"
    INITIALIZED = "Initialized"
    WAITING_APPROVAL = "Waiting approval"
    APPROVED = "Approved"
    IN_PROGRESS = "In progress"
    COMPLETED = "Completed"
    DECLINED = "Declined"
    
    NOT_COMPLETED = "Not completed" # Все, кроме COMPLETED
    ALL = "All" # Все

class OrderRenewState(str, Enum):
    """Статус обновления сертификата"""
    
    RENEW = "Renew"
    CANCELED = "Canceled"



class TaskType(str, Enum):
    ORDER = "Order"
    RENEW = "Renew"
    RENEW_MANUALLY = "Renew manually"
    CHANGE = "Change"
    CHANGE_MANUALLY = "Change manually"
    CUSTOM = "Custom"
    EMPTY = "Empty"


class TaskState(str, Enum):
    NEW = "New"
    PENDING = "Pending"
    STARTED = "Started"
    FAILED = "Failed"
    SUCCEEDED = "Succeeded"
    RETRYING = "Retrying"
    REVOKED = "Revoked"
    
    
class TaskStatus(str, Enum):
    NEW = "New"
    PENDING = "Pending"
    IN_PROGRESS = "In progress"
    STARTED = "Started"
    FAILED = "Failed"
    SUCCEEDED = "Succeeded"
    RETRYING = "Retrying"
    REVOKED = "Revoked"




class TaskStepState(str, Enum):
    NEW = "New"
    AWAITING_APPROVAL = "Awaiting approval"
    APPROVED = "Approved"
    REJECTED = "Rejected"
    # PENDING = "Pending"
    # STARTED = "Started"
    # FAILED = "Failed"
    # SUCCEEDED = "Succeeded"
    RETRYING = "Retrying"
    # REVOKED = "Revoked"
    # DONE = "Done"
    COMPLETED = "Completed"
    HALTED = "Halted"
    


class TaskStepStatus(str, Enum):
    NEW = "New"
    PENDING = "Pending"
    IN_PROGRESS = "In progress"
    # STARTED = "Started"
    FAILED = "Failed"
    # SUCCEEDED = "Succeeded"
    # RETRYING = "Retrying"
    REVOKED = "Revoked"
    CANCELLED = 'Cancelled'
    # DONE = "Done"
    COMPLETED = "Completed"
    MANUAL = "Manual"


class TaskStepType(str, Enum):
    START = "Start"
    END = "End"
    # CHECK = "Check"
    APPROVE = "Approve"
    NOTIFY = "Notify"
    DNS_EXT_CREATE = "DNS external create"
    DNS_EXT_VALIDATE = "DNS external validate"
    DNS_EXT_DELETE = "DNS external delete"
    DNS_INT_CREATE = "DNS internal create"
    DNS_INT_VALIDATE = "DNS internal validate"
    DNS_INT_DELETE = "DNS internal delete"
    # KEY_CREATE = "Key create"
    REQUEST_CREATE = "Request create"
    CERTIFICATE_GET = "Certificate get from CA"
    CA_CREATE_ORDER = "CA create order"
    ORDER_FINALIZE = "Finalize order"
    

class OrderTask(str, Enum):
    ORDER_CREATE = "order_create"
    SEND_AFTER_JOB_NOTIFICATION = "send_user_notification_revoking_access"
    GRANT_ACCESS_TO_PERFORMERS = "grant_access_to_performers"
    REVOKE_ACCESS_FROM_PERFORMERS = "revoke_access_from_performers"
    GRANT_EMERGENCY_ACCESS_TO_USER = "grant_access_host_by_ad_login"
    REVOKE_EMERGENCY_ACCESS_TO_USER = "revoke_access_by_operation_id"


TASK_STEP_MAP = {
    TaskStepType.APPROVE: "send_user_notification_revoking_access",
    TaskStepType.REQUEST_CREATE: "request_create",
    TaskStepType.DNS_EXT_CREATE: "dns_ext_create",
    TaskStepType.DNS_EXT_VALIDATE: "dns_ext_validate",
    TaskStepType.DNS_EXT_DELETE: "dns_ext_delete",
    TaskStepType.CERTIFICATE_GET: "certificate_get",
    TaskStepType.ORDER_FINALIZE: "order_finalize",
    # TaskStepType.DNS_EXT_CREATE: "",
}

class JobState(str, Enum):
    STARTED = "Started"
    FAILED = "Failed"
    SUCCEEDED = "Succeeded"
    NOT_FINISHED = "Not finished"


class Color(str, Enum):
    YELLOW = "#FFE034"
    GOLD = "#FFD700"
    LIGHTGRAY = "#D3D3D3"
    SILVER = "#C0C0C0"
    GRAY = "#808080"
    BLACK = "#000000"
    RED = "#FF0000"
    CRIMSON = "#DC143C"
    PINK = "#FFC0CB"
    DEEPPINK = "#FF1493"
    ORANGERED = "#FF4500"
    ORANGE = "#FFA500"
    VIOLET = "#EE82EE"
    MAGENTA = "#FF00FF"
    PURPLE = "#800080"
    INDIGO = "#4B0082"
    LIME = "#00FF00"
    GREEN = "#008000"
    LIMEGREEN = "#32CD32"
    CYAN = "#00FFFF"
    SKYBLUE = "#87CEEB"
    BLUE = "#0000FF"
    NAVY = "#000080"
    TAN = "#D2B48C"
    BROWN = "#A52A2A"
    WHITE = "#FFFFFF"
    AZURE = "#F0FFFF"
    HONEYDEW = "#F0FFF0"
    SEASHELL = "#FFF5EE"
    IVORY = "#FFFFF0"
    
    
