from django.shortcuts import render
from django.http import HttpResponse
from ratelimit.decorators import ratelimit

# Authenticated users: 10 requests/min
# Anonymous users: 5 requests/min

@ratelimit(key='ip', rate='10/m', method='GET', block=True)
def sensitive_view(request):
    """
    Example sensitive view that is rate-limited.
    """
    return HttpResponse("This is a rate-limited view.")
