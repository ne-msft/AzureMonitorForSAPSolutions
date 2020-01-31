from helper.v1_8 import *
from helper.updateprofile import *
versionClassDict = dict()
versionClassDict["v1.5"]="v1_5"
versionClassDict["v1.8"]="v1_8"
class updateProfileFactory():
    def createUpdateProfile(self, version):
        return globals()[versionClassDict[version]]()