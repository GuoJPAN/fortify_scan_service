from django.urls import path

from .views import *

urlpatterns = [
    path('', index, name='index'),
    path('projectInfo', display_project, name='display_project'),
    path('startGitScan', fortify_scan, name='fortify_scan'),
    path('vDetail', v_detail, name='v_detail'),
    path('test', start_git_scan, name='fortify_scan'),
    path('singleVulDetail', single_vul_detail, name='single_vul_detail'),
    path('deletePrj', del_prj_info, name='删除扫描'),
    path('vulLevelTotal', vul_level_total, name='获取各漏洞等级的总数'),
]