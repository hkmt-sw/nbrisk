from netbox.filtersets import NetBoxModelFilterSet
from django.db.models import Q
import django_filters
from . import choices, models

# ThreatSource Filters


class ThreatSourceFilterSet(NetBoxModelFilterSet):
    threat_type = django_filters.MultipleChoiceFilter(choices=choices.ThreatTypeChoices, null_value=None)
    capability = django_filters.MultipleChoiceFilter(choices=choices.CapabilityChoices, null_value=None)
    class Meta:
        model = models.ThreatSource
        fields = ["id", "name", "threat_type", "capability", "intent", "targeting", "description", "notes"]


# ThreatEvent Filters


class ThreatEventFilterSet(NetBoxModelFilterSet):
    relevance = django_filters.MultipleChoiceFilter(choices=choices.RelevanceChoices, null_value=None)
    likelihood = django_filters.MultipleChoiceFilter(choices=choices.LikelihoodChoices, null_value=None)
    impact = django_filters.MultipleChoiceFilter(choices=choices.ImpactChoices, null_value=None)
    class Meta:
        model = models.ThreatEvent
        fields = ["threat_source", "relevance", "likelihood", "impact"]


# Vulnerability Filters


class VulnerabilityFilterSet(NetBoxModelFilterSet):
    in_kev = django_filters.BooleanFilter()

    class Meta:
        model = models.Vulnerability
        fields = [
            "id",
            "name",
            "cve",
            "in_kev",
            "description",
            "notes",
            "cvssaccessVector",
            "cvssaccessComplexity",
            "cvssauthentication",
            "cvssconfidentialityImpact",
            "cvssintegrityImpact",
            "cvssavailabilityImpact",
            "cvssbaseScore",
            "kev_date_added",
            "kev_ransomware_use",
            "kev_required_action",
            "kev_due_date",
            "kev_vendor_project",
            "kev_product",
            "epss_score",
            "epss_percentile",
            "epss_date",
            ]

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        qs_filter = (
            Q(name__icontains=value)
            | Q(cve__icontains=value)
            | Q(cvssaccessVector__icontains=value)
        )
        return queryset.filter(qs_filter)


# VulnerabilityAssignment Filters


class VulnerabilityAssignmentFilterSet(NetBoxModelFilterSet):
    
    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        qs_filter = (
            Q(vulnerability__name__icontains=value) 
            | Q(vulnerability__cve__icontains=value)
        )
        return queryset.filter(qs_filter)

    class Meta:
        model = models.VulnerabilityAssignment
        fields = ["vulnerability"]


# Risk Filters


class RiskFilterSet(NetBoxModelFilterSet):
    likelihood = django_filters.MultipleChoiceFilter(choices=choices.LikelihoodChoices, null_value=None)
    impact = django_filters.MultipleChoiceFilter(choices=choices.ImpactChoices, null_value=None)
    class Meta:
        model = models.Risk
        fields = ["name", "threat_event", "description", "impact", "likelihood"]

# Control Filters

class ControlFilterSet(NetBoxModelFilterSet):
    category = django_filters.MultipleChoiceFilter(choices=choices.ControlCategoryChoices, null_value=None)
    class Meta:
        model = models.Control
        fields = [
            "name",
            "description",
            "notes",
            "category",
            "risk",
        ]

# CPEMapping FilterSet

class CPEMappingFilterSet(NetBoxModelFilterSet):
    cpe_part = django_filters.MultipleChoiceFilter(choices=models.CPE_PART_CHOICES, null_value=None)
    platform_id = django_filters.ModelMultipleChoiceFilter(
        queryset=__import__('dcim.models', fromlist=['Platform']).Platform.objects.all(),
    )
    device_type_id = django_filters.ModelMultipleChoiceFilter(
        queryset=__import__('dcim.models', fromlist=['DeviceType']).DeviceType.objects.all(),
    )
    verified = django_filters.BooleanFilter()

    class Meta:
        model = models.CPEMapping
        fields = ['platform_id', 'device_type_id', 'cpe_vendor', 'cpe_product', 'cpe_part', 'verified']
