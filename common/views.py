from django.shortcuts import render
from django.http import JsonResponse, HttpResponseRedirect
from django.http.response import HttpResponse
from django.contrib import auth
import json
from django.contrib.auth import logout


# 调试用的代码
def login(request):
    data = json.loads(request.body)
    username = data['username']
    password = data['password']
    user = auth.authenticate(username=username, password=password)  # 进行认证
    if user:
        request.session['is_login'] = True  # 设置session的随机字段值
        data = {"status": 0, "msg": "登录成功！！！", 'data': data}
        return HttpResponse(json.dumps(data, ensure_ascii=False))
    else:
        data = {"status": 500, "msg": "登录失败，请检查用户名密码是否正确！！！", 'data': data}
        return HttpResponse(json.dumps(data, ensure_ascii=False))


def log_out(request):
    if request.user:
        logout(request)
    return JsonResponse({"status": 401, "msg": "退出成功"}, json_dumps_params={'ensure_ascii': False}, safe=False)