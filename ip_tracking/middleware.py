from django.core.cache import cache
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP
import requests

class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        # Block IPs
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Forbidden: Your IP is blocked.")

        # Get geolocation from cache or API
        geo_data = cache.get(f"geo_{ip}")
        if not geo_data:
            geo_data = self.get_geolocation(ip)
            if geo_data:
                # Cache for 24 hours
                cache.set(f"geo_{ip}", geo_data, 60 * 60 * 24)

        country = geo_data.get('country') if geo_data else None
        city = geo_data.get('city') if geo_data else None

        # Log the request
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            country=country,
            city=city
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def get_geolocation(self, ip):
        try:
            # Free API: ip-api.com
            response = requests.get(f"http://ip-api.com/json/{ip}")
            data = response.json()
            if data['status'] == 'success':
                return {'country': data.get('country'), 'city': data.get('city')}
        except Exception:
            pass
        return None
