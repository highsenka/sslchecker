from datetime import datetime, timezone, timedelta


def now_utc() -> datetime:
    return datetime.utcnow().replace(tzinfo=timezone.utc)

def eol_utc() -> datetime:
    return datetime.strptime('2100-01-01 00:00:00', '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
