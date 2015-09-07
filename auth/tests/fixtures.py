from datetime import datetime
import django.utils.timezone
from django_dynamic_fixture import G
import django.contrib.auth.models


time_now = lambda: datetime.utcnow().replace(tzinfo=django.utils.timezone.utc)

def load_auth_users():
    model = G(django.contrib.auth.models.User, fill_nullable_fields=False)

    model.first_name = str()
    model.is_staff = True
    model.groups = []
    model.last_login = time_now()
    model.username = 'lupco'
    model.is_active = True
    model.last_name = str()
    model.email = str()
    model.date_joined = time_now()
    model.is_superuser = True
    model.password = ('pbkdf2_sha256$20000$xlF1EslIazCK$'
                      'qG3IGdOLfns9Or0Fj+V6yJlDKR922XQ6h4zNr09lwvg=')
    model.user_permissions = []
    model.pk = 1
    model.save()

    return model
