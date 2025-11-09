from celery import shared_task
from datetime import datetime, timedelta
from django.utils import timezone
from .models import RequestLog, SuspiciousIP

@shared_task
def detect_suspicious_ips():
    """
    Flag IPs that are suspicious:
    - More than 100 requests in the last hour
    - Accessing sensitive paths (/admin, /login)
    """
    one_hour_ago = timezone.now() - timedelta(hours=1)
    sensitive_paths = ['/admin', '/login']

    # Group requests by IP
    ip_request_counts = {}
    suspicious_ips = set()

    logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)
    for log in logs:
        ip = log.ip_address
        ip_request_counts[ip] = ip_request_counts.get(ip, 0) + 1

        if log.path in sensitive_paths:
            suspicious_ips.add((ip, f"Accessed sensitive path: {log.path}"))

    # Flag IPs with >100 requests/hour
    for ip, count in ip_request_counts.items():
        if count > 100:
            suspicious_ips.add((ip, f"High request volume: {count} requests in the last hour"))

    # Save to SuspiciousIP model
    for ip, reason in suspicious_ips:
        SuspiciousIP.objects.create(ip_address=ip, reason=reason)
