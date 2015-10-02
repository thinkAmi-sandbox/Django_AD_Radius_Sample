from django.contrib.auth import get_user_model
from django.conf import settings
from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessRequest, AccessAccept
import six
import os

class RadiusPAPBackend(object):
    def authenticate(self, username=None, password=None):
        srv = Client(
            server=settings.AD_NPS_HOST_NAME,
            # secretを`six.binary_type`型にしていない場合、以下のエラーが発生する
            # TypeError: secret must be a binary string
            # そのため、six.b()を使ってbinary_typeにする
            secret=six.b(settings.AD_NPS_SHARED_SECRETS),
            # RADIUSではDictionaryの指定が必要
            # 今回はpyradのexampleにあったdictionaryをプロジェクト直下に置いて使用
            dict=Dictionary(os.path.join(settings.BASE_DIR, "dictionary")),
        )
        req = srv.CreateAuthPacket(
            code=AccessRequest,
            User_Name=username,
        )

        # NPSの接続要求ポリシーで、条件にFramed-Protocolを`PPP`として指定したため、
        # pyrad側でもFramed-Protocolを明示的に指定する
        # `1`が`PPP`に該当する
        req['Framed-Protocol'] = 1

        # User-Password方式なので、PwCrypt()を使用する
        req['User-Password'] = req.PwCrypt(password)

        try:
            reply = srv.SendPacket(req)
            if reply.code == AccessAccept:
                user = get_user_model()
                result, created = user.objects.update_or_create(
                    username = username,
                    password = password
                )
                return result
            else:
                return None

        except:
            return None


    def get_user(self, user_id):
        user = get_user_model()
        try:
            return user.objects.get(pk=user_id)
        except:
            return None
