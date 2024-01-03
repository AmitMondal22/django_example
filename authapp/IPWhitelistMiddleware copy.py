from django.http import HttpResponseForbidden

class IPWhitelistMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Define your IP whitelist
        ip_whitelist = ['127.0.0.1', '192.168.1.1','127.0.0.1:7000']  # Add your allowed IP addresses

        # Get the client's IP address
        client_ip = self.get_client_ip(request)

        # Check if the client's IP is in the whitelist
        if client_ip not in ip_whitelist:
            return HttpResponseForbidden("Access denied. Your IP is not in the whitelist.")

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip