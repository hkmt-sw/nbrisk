from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db.models import Q

from netbox.context import current_request
from netbox.plugins.utils import get_plugin_config

ASSET_NOT_FOUND = "Asset not found or not a supported asset type."


def asset_types_q():
    """
    Q object matching the asset types configured in PLUGINS_CONFIG (supported_assets + additional_assets).
    These are the models that show the "Add Vulnerability" button.
    """
    labels = (get_plugin_config('nb_risk', 'supported_assets') or []) + \
        (get_plugin_config('nb_risk', 'additional_assets') or [])
    q = Q(pk__in=[])
    for label in labels:
        app_label, _, model = label.partition('.')
        q |= Q(app_label=app_label, model=model.lower())
    return q


def supported_asset_types():
    """Content types that can carry a vulnerability assignment."""
    return ContentType.objects.filter(asset_types_q())


def get_asset(object_type, asset_id, user=None):
    """
    Return the asset identified by (object_type, asset_id) if it is a supported asset type and visible to the user.

    The user defaults to the one of the current request. Unsupported types, missing objects and objects the user
    may not view all raise the same ValidationError, so the response does not reveal which objects exist.
    """
    if user is None and (request := current_request.get()) is not None:
        user = request.user
    if object_type is None or asset_id in (None, ''):
        raise ValidationError(ASSET_NOT_FOUND)
    if not supported_asset_types().filter(pk=object_type.pk).exists():
        raise ValidationError(ASSET_NOT_FOUND)
    model = object_type.model_class()
    if model is None:
        raise ValidationError(ASSET_NOT_FOUND)
    queryset = model.objects.all()
    if user is not None:
        queryset = queryset.restrict(user, 'view')
    try:
        return queryset.get(pk=asset_id)
    except (model.DoesNotExist, ValueError, TypeError):
        raise ValidationError(ASSET_NOT_FOUND)
