#!/usr/bin/env python3
#
#       Azure Monitor for SAP Solutions payload script
#       (deployed on collector VM)
#
#       License:        GNU General Public License (GPL)
#       (c) 2020        Microsoft Corp.
#

class updateProfile(object):
    updatefunc = None
    def update(self,ctx,previousVersion):
        self.updatefunc(ctx, previousVersion)
