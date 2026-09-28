from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError

from netbox.context import current_request

from . import choices

ASSET_NOT_FOUND = "Asset not found or not a supported asset type."


def supported_asset_types():
    """Content types that can carry a vulnerability assignment (see choices.AssetTypes)."""
    return ContentType.objects.filter(choices.AssetTypes)


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
