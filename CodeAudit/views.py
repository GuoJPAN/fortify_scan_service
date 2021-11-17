from django.shortcuts import render
from django.http import JsonResponse, HttpResponseRedirect
from django.http.response import HttpResponse
from CodeAudit.fortify_scan import *
import json
from .info import information
from utils.auth import log_in


# Create your views here.


def index(request):
    return render(request, 'index.html')


@log_in
def fortify_scan(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        t = data['type']  # 1为git,2为git-list,3为SVN,4为上传
        if (t == "1"):
            gitaddress = data['git_path']
            gitbranch = data['git_branch']
            storeHouseType = data['storeHouseType']
            push.delay(gitaddress=gitaddress, gitbranch=gitbranch, storeHouseType=storeHouseType)
            return JsonResponse({"code": 1001, "msg": "开始扫描"})
        elif (t == "2"):
            git_api()
            return JsonResponse({"code": 1001, "msg": "开始扫描!!!"})
        elif (t == "3"):
            svnaddress = request.POST.get("svn_address")
            svnaccount = request.POST.get("svn_username")
            svnpwd = request.POST.get("svn_password")
            push.delay(svnaddress=svnaddress, type=3, svnaccount=svnaccount, svnpwd=svnpwd)
            return JsonResponse({"status": 0, "msg": "开始扫描!!!"})
        elif (t == "4"):
            myFile = request.FILES.get("file", None)
            name = myFile.name
            if not myFile:
                return JsonResponse({"status": 0, "msg": "上传失败!!!"})
            elif myFile.name.split('.')[-1] != 'zip':
                return JsonResponse({"status": 2, "msg": "上传文件必须为ZIP!!!"})
            else:
                destination = open(os.path.join("/data/fortify/", myFile.name), 'wb+')
                for chunk in myFile.chunks():
                    destination.write(chunk)
                destination.close()
                # os.system("unzip -o  /data/fortify/" + myFile.name + "  -d  /data/fortify/" + name.split('.')[0])
                os.system("unzip -o  /data/fortify/" + myFile.name + "  -d  /data/fortify/")
                push.delay(name=name.split('.')[0], type=4)
                return JsonResponse({"status": 1, "msg": "上传成功!!!"})

        else:
            return JsonResponse({"status": 0, "msg": "参数类型错误"})

    else:
        address = GIT_ADDRESS
        p = GIT_PARM
        choice = GIT_API_CHOICE
        filepath = GIT_PATH
        return render(request, "audit/scan.html", locals())


@log_in
def display_project(request):
    # if request.method == 'GTE':
    # data = json.loads(request.body)
    json_list = []
    proj_infos = proj_info.objects.all().order_by('-id')
    # print(proj_infos)
    for project in proj_infos:
        json_dict = {}
        json_dict["id"] = project.id
        json_dict["name"] = project.name
        json_dict["total"] = project.total
        json_dict["git"] = project.git
        json_dict["gitbranch"] = project.gitbranch
        if project.status == 1:
            json_dict["status"] = "进行中"
        elif project.status == 2:
            json_dict["status"] = "已完成"
        else:
            json_dict["status"] = "扫描失败"
        if project.type == 1:
            json_dict["type"] = "GIT"
        elif project.type == 2:
            json_dict["type"] = "SVN"
        else:
            json_dict["type"] = "压缩包"
        json_dict["svn"] = project.svn
        json_dict["time"] = project.time.strftime('%Y-%m-%d-%H:%M:%S')
        json_list.append(json_dict)
    data = {"status": 0, "msg": "OK!!!", 'data': json_list}
    return JsonResponse(data)


@log_in
def v_detail(request):
    '''
    获取fortify扫描结果详情
    :param request: projectID
    :return:
    '''
    if request.method == 'POST':
        data = json.loads(request.body)
        proj_id = data["projectID"]
        json_list = []
        vul_infos = vul_info.objects.filter(proj_id=proj_id).order_by('risk')
        for vrl in vul_infos:
            json_dict = {}
            json_dict["vid"] = vrl.vid
            json_dict["title"] = vrl.title
            json_dict["vtoken"] = vrl.vtoken
            json_dict["risk"] = vrl.risk
            json_dict["Abstract"] = vrl.Abstract
            json_dict["FileName"] = vrl.FileName
            json_dict["FilePath"] = vrl.FilePath
            json_dict["LineStart"] = vrl.LineStart
            json_dict["Snippet"] = vrl.Snippet
            json_dict["full_code"] = vrl.full_code
            json_dict["extend"] = vrl.extend
            json_dict["proj_id"] = str(vrl.proj_id)
            json_dict["time"] = vrl.time.strftime('%Y-%m-%d-%H:%M:%S')
            json_list.append(json_dict)
        data = {"status": 0, "msg": "获取数据成功", 'data': json_list}
        return JsonResponse(data)
    else:
        data = {"status": 500, "msg": "系统错误", 'data': ""}
        return JsonResponse(data)

@log_in
def single_vul_detail(request):
    '''
    获取fortify扫描结果详情
    :param request: projectID
    :return:
    '''
    if request.method == 'POST':
        data = json.loads(request.body)
        proj_id = data["projectID"]
        vtoken = data["vtoken"]
        json_list = []
        vul_infos = vul_info.objects.filter(vtoken=vtoken).order_by('risk')
        for vrl in vul_infos:
            json_dict = {}
            json_dict["vid"] = vrl.vid
            json_dict["title"] = vrl.title
            json_dict["risk"] = vrl.risk
            json_dict["Abstract"] = vrl.Abstract
            json_dict["FileName"] = vrl.FileName
            json_dict["FilePath"] = vrl.FilePath
            json_dict["LineStart"] = vrl.LineStart
            json_dict["Snippet"] = vrl.Snippet
            json_dict["full_code"] = vrl.full_code
            json_dict["extend"] = vrl.extend
            json_dict["proj_id"] = vrl.proj_id.type
            json_dict["vtoken"] = vrl.vtoken
            json_dict["describe"] = information(vrl.title)['describe']
            json_dict["Recommendation"] = information(vrl.title)['Recommendation']
            json_dict["time"] = vrl.time.strftime('%Y-%m-%d-%H:%M:%S')
            json_list.append(json_dict)
        data = {"status": 0, "msg": "获取数据成功", 'data': json_list}
        return JsonResponse(data)
    else:
        data = {"status": 500, "msg": "系统错误", 'data': ""}
        return JsonResponse(data)

@log_in
# 调试用的代码
def start_git_scan(request):
    # git_path = request.POST.get('git_path')
    # git_user = request.POST.get('git_user')
    # git_pwd = request.POST.get('git_pwd')
    info = {
        "git_path": "git_path",
        "git_user": "git_user",
        "git_pwd": "git_pwd"
    }
    data = {"status": 0, "msg": "扫描成功!!!", 'data': info}

    return HttpResponse(json.dumps(data, ensure_ascii=False))


@log_in
def del_prj_info(request):
    '''
    根据项目ID删除扫描项目信息及扫描结果详情
    :param request:
    :return:
    '''
    if request.method == 'POST':
        data = json.loads(request.body)
        proj_id = data["projectID"]
        try:
            proj_info.objects.filter(id=proj_id).delete()
            vul_info.objects.filter(proj_id=proj_id).delete()
            data = {"status": 2, "msg": "删除成功!!!", 'data': ""}
            return HttpResponse(json.dumps(data, ensure_ascii=False))
        except Exception as e:
            print(str(e))
            data = {"status": 2, "msg": "删除失败!!!", 'data': ""}
            return HttpResponse(json.dumps(data, ensure_ascii=False))


@log_in
def vul_level_total(request):
    '''
    获取各风险等级漏洞综总数
    :param request:
    :return:
    '''
    if request.method == 'GET':

        print(vul_info.objects.filter(risk='High').count())
        vul_critical = vul_info.objects.filter(risk='Critical').count()
        vul_high = vul_info.objects.filter(risk='High').count()
        vul_medium = vul_info.objects.filter(risk='Medium').count()
        vul_low = vul_info.objects.filter(risk='Low').count()
        data = {"status": 200, "msg": "ok", 'data': {
            "Critical": vul_critical,
            "High": vul_high,
            "Medium": vul_medium,
            "Low": vul_low,
            "Total": vul_critical + vul_high + vul_medium + vul_low
        }}
        return JsonResponse(data)
    else:
        data = {"status": 500, "msg": "系统错误", 'data': ""}
        return JsonResponse(data)
