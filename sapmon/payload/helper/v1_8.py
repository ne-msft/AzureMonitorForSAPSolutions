import json
from helper.azure import *
from helper.context import Context
from helper.tools import *
from helper.updateprofile import updateProfile

class v1_8(updateProfile):
    # This function will configure the content of the keyvault according to the requirements of version v1.8
    # To upgrade to version v1.8 from v1.5 we will need to update the format of the secrets
    # stored in the keyvault as v1.8> v1.6(first version with multi instance support) requires
    # the secrets to be stored in an array of dictionary of secrets

    def update(self, ctx: Context, previousVersion: str):
        secrets = ctx.azKv.getCurrentSecrets()
        hanaSecrets = sliceDict(secrets, HanaSecretName)["SapHana"]
        hanaSecretsJson = json.loads(hanaSecrets)
        # if previous version is v1_5 then the stored keyvault secret is a plain JSON containing credentials for a single instance
        # any version above v1.5 will require the stored secret to be of type [comma separated credentials in JSON format]
        if previousVersion == "v1.5":
            reHanaSecrets = json.dumps([hanaSecretsJson])
            ctx.azKv.setSecret(HanaSecretName, reHanaSecrets)

    updatefunc = update

