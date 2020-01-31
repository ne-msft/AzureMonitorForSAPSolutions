# This script will configure the content of the keyvault according to the requirements of a specific version
# of the monitor. For example to upgrade to a version v1.6 from v1.5 we will need to update the format of the secrets
# stored in the keyvault as v1.6(first version with multi instance support) requires the secrets to be stored in a specific format.
versionClassDict = dict()
versionClassDict["v1.5"]="v1_5"
versionClassDict["v1.8"]="v1_8"
class updateProfile(object):
    updatefunc = None
    def update(self,ctx,previousVersion):
        self.updatefunc(ctx, previousVersion)

class updateProfileFactory():
    def createUpdateProfile(self, version):
        return globals()[versionClassDict[version]]()