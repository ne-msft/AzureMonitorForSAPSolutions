import json
from tools import *
from provider.saphana import HanaSecretName
from updateprofile import updateProfile
from context import _Context
from azure import *

class v1_8(updateProfile):
    def update(self, ctx: _Context, previousVersion: str):
        secrets = ctx.azKv.getCurrentSecrets()
        hanaSecrets = sliceDict(secrets, HanaSecretName)
        jSecrets = json.loads(hanaSecrets)
        # if previous version is v1_5 then the stored keyvault secret is a plain JSON containing credentials for a single instance
        # any version above v1.5 will require the stored secret to be of type [comma separated credentials in JSON format]
        if previousVersion == "v1_5":
            reHanaSecrets = json.dumps([jSecrets])
            ctx.azKv.setSecret(HanaSecretName, reHanaSecrets)

    updatefunc = update

