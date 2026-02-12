import uuid


def generate_uuid() -> str:
    return str(uuid.uuid4())


def generate_request_id() -> str:
    return generate_uuid()
