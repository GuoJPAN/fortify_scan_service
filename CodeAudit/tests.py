import subprocess, os

subprocess.Popen(["rm", "-rf", "/data/fortify/javaTest/"])
subprocess.Popen(["rm", "-f", "/data/fortify/report/javaTest.xml"])
subprocess.Popen(["rm", "-f", "/data/fortify/report/javaTest.fpr"])