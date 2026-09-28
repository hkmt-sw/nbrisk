from django.core.exceptions import ValidationError as DjangoValidationError
from dcim.api.serializers import DeviceTypeSerializer, PlatformSerializer
from rest_framework import serializers
from netbox.api.fields import ChoiceField, ContentTypeField
from netbox.api.gfk_fields import GFKSerializerField
from netbox.api.serializers import NetBoxModelSerializer
from core.models import ObjectType

from .. import models, choices
from ..utils import get_asset

# ThreatSource Serializers

class ThreatSourceSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nb_risk-api:threatsource-detail")
    display = serializers.SerializerMethodField('get_display')
    threat_type = ChoiceField(choices=choices.ThreatTypeChoices)
    capability = ChoiceField(choices=choices.CapabilityChoices)

    def get_display(self, obj):
        return obj.name

    class Meta:
        model = models.ThreatSource
        fields = [
            "id",
            "url",
            "display",
            "name",
            "threat_type",
            "capability",
            "intent",
            "targeting",
            "description",
        ]
        brief_fields = ['id', 'url', 'display', 'name', 'description']

# ThreatEvent Serializers

class ThreatEventSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nb_risk-api:threatevent-detail")
    display = serializers.SerializerMethodField('get_display')
    threat_source = serializers.SlugRelatedField(slug_field="name", queryset=models.ThreatSource.objects.all())
    relevance = ChoiceField(choices=choices.RelevanceChoices)
    likelihood = ChoiceField(choices=choices.LikelihoodChoices)

    def get_display(self, obj):
        return obj.name

    class Meta:
        model = models.ThreatEvent
        fields = [
            "id",
            "url",
            "display",
            "name",
            "threat_source",
            "relevance",
            "likelihood",
            "impact",
            "vulnerability",
        ]
        brief_fields = ['id', 'url', 'display', 'name', 'description']

# Vulnerability Serializers

class VulnerabilitySerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nb_risk-api:vulnerability-detail")
    display = serializers.SerializerMethodField('get_display')

    def get_display(self, obj):
        return obj.name

    class Meta:
        model = models.Vulnerability
        fields = [
            "id",
            "url",
            "display",
            "name",
            "cve",
            "description",
            "notes",
            "in_kev",
            "kev_date_added",
            "kev_ransomware_use",
            "kev_required_action",
            "kev_due_date",
            "kev_vendor_project",
            "kev_product",
            "epss_score",
            "epss_percentile",
            "epss_date",
            "cvssaccessVector",
            "cvssaccessComplexity",
            "cvssauthentication",
            "cvssconfidentialityImpact",
            "cvssintegrityImpact",
            "cvssavailabilityImpact",
            "cvssbaseScore",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        ]
        brief_fields = ['id', 'url', 'display', 'name', 'description']


# VulnerabilityAssignment Serializers

class VulnerabilityAssignmentSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nb_risk-api:vulnerabilityassignment-detail")
    display = serializers.SerializerMethodField('get_display')

    # Use ObjectType (NetBox wrapper) filtered via the AssetTypes Q object for the content type field.
    # Pass the Q object correctly as a positional filter argument.
    asset_object_type = ContentTypeField(
        queryset=ObjectType.objects.filter(choices.AssetTypes),
        required=True,
    )

    # GFKSerializerField replaces the manual get_serializer_for_model() pattern (NetBox 4.5+)
    asset = GFKSerializerField(read_only=True)

    vulnerability = serializers.SlugRelatedField(slug_field="name", queryset=models.Vulnerability.objects.all())

    asset_id = serializers.IntegerField(write_only=True)

    def validate(self, data):
        # The asset must be a supported type and visible to the requesting user (object-level permissions).
        asset_object_type = data.get('asset_object_type', getattr(self.instance, 'asset_object_type', None))
        asset_id = data.get('asset_id', getattr(self.instance, 'asset_id', None))
        if 'asset_object_type' in data or 'asset_id' in data or self.instance is None:
            request = self.context.get('request')
            try:
                asset = get_asset(asset_object_type, asset_id, user=getattr(request, 'user', None))
            except DjangoValidationError as e:
                raise serializers.ValidationError({'asset_id': e.messages})
            data['asset_id'] = asset.pk
        return super().validate(data)

    def get_display(self, obj):
        return obj.name

    class Meta:
        model = models.VulnerabilityAssignment
        fields = [
            "id",
            "url",
            "display",
            "asset_object_type",
            "asset_id",
            "asset",
            "vulnerability",
        ]
        brief_fields = ['id', 'url', 'display']

# Risk Serializers

class RiskSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nb_risk-api:risk-detail")
    display = serializers.SerializerMethodField('get_display')
    threat_event = serializers.SlugRelatedField(slug_field="name", queryset=models.ThreatEvent.objects.all())

    def get_display(self, obj):
        return obj.name

    class Meta:
        model = models.Risk
        fields = [
            "id",
            "url",
            "display",
            "threat_event",
            "description",
            "likelihood",
            "impact",
            "notes",
        ]

# Control Serializers

class ControlSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nb_risk-api:control-detail")
    display = serializers.SerializerMethodField('get_display')
    risk = RiskSerializer(many=True, required=False, allow_null=True, nested=True)

    def get_display(self, obj):
        return obj.name

    class Meta:
        model = models.Control
        fields = [
            "id",
            "url",
            "display",
            "name",
            "description",
            "notes",
            "risk",
        ]


# CPEMapping Serializers

class CPEMappingSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nb_risk-api:cpemapping-detail")
    display = serializers.SerializerMethodField('get_display')
    # Writable nested references (a pk or {"id": ...} is accepted). These used to be read-only method
    # fields, so CPE mappings could not be created through the API.
    platform = PlatformSerializer(nested=True, required=False, allow_null=True)
    device_type = DeviceTypeSerializer(nested=True, required=False, allow_null=True)

    def get_display(self, obj):
        return str(obj)

    class Meta:
        model = models.CPEMapping
        fields = [
            'id', 'url', 'display',
            'platform', 'device_type',
            'cpe_part', 'cpe_vendor', 'cpe_product', 'cpe_target_sw',
            'verified', 'notes',
        ]
        brief_fields = ['id', 'url', 'display', 'cpe_vendor', 'cpe_product']
