from django.http.response import HttpResponse
import json


def log_in(func):
    def warpper(request, *args, **kwargs):
        is_login = request.session.get('is_login', False)
        if not is_login:
            data = {"status": 401, "msg": "用户未登录！！！", 'data': ""}
            return HttpResponse(json.dumps(data, ensure_ascii=False))
        return func(request, *args, **kwargs)
    return warpper