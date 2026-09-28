from django.db.models import Q
from utilities.choices import ChoiceSet

# Define a set of choices for the Threat Type
class ThreatTypeChoices(ChoiceSet):

    THREAT_TYPE_1 = "ADVERSARIAL"
    THREAT_TYPE_2 = "ACCIDENTAL"
    THREAT_TYPE_3 = "STRUCTURAL"
    THREAT_TYPE_4 = "ENVIRONMENTAL"

    # Beszédes álnevek (a tesztek és a külső kód ezeket használják)
    ADVERSARIAL = THREAT_TYPE_1
    ACCIDENTAL = THREAT_TYPE_2
    STRUCTURAL = THREAT_TYPE_3
    ENVIRONMENTAL = THREAT_TYPE_4

    CHOICES = (
        (THREAT_TYPE_1, "ADVERSARIAL"),
        (THREAT_TYPE_2, "ACCIDENTAL"),
        (THREAT_TYPE_3, "STRUCTURAL"),
        (THREAT_TYPE_4, "ENVIRONMENTAL"),
    )


# Define a set of choices for the Capability
class CapabilityChoices(ChoiceSet):

    CAPABILITY_1 = "Very High"
    CAPABILITY_2 = "High"
    CAPABILITY_3 = "Moderate"
    CAPABILITY_4 = "Low"
    CAPABILITY_5 = "Very Low"

    # Beszédes álnevek
    VERY_HIGH = CAPABILITY_1
    HIGH = CAPABILITY_2
    MODERATE = CAPABILITY_3
    MEDIUM = CAPABILITY_3
    LOW = CAPABILITY_4
    VERY_LOW = CAPABILITY_5

    CHOICES = (
        (CAPABILITY_1, "Very High"),
        (CAPABILITY_2, "High"),
        (CAPABILITY_3, "Moderate"),
        (CAPABILITY_4, "Low"),
        (CAPABILITY_5, "Very Low"),
    )


# Define a set of choices for the Relevance


class RelevanceChoices(ChoiceSet):

    RELEVANCE_1 = "Confirmed"
    RELEVANCE_2 = "Expected"
    RELEVANCE_3 = "Anticipated"
    RELEVANCE_4 = "Predicted"
    RELEVANCE_5 = "Possible"
    RELEVANCE_6 = "N/A"

    # Beszédes álnevek
    CONFIRMED = RELEVANCE_1
    RELEVANT = RELEVANCE_1
    EXPECTED = RELEVANCE_2
    ANTICIPATED = RELEVANCE_3
    PREDICTED = RELEVANCE_4
    POSSIBLE = RELEVANCE_5
    NOT_APPLICABLE = RELEVANCE_6

    CHOICES = (
        (RELEVANCE_1, "Confirmed"),
        (RELEVANCE_2, "Expected"),
        (RELEVANCE_3, "Anticipated"),
        (RELEVANCE_4, "Predicted"),
        (RELEVANCE_5, "Possible"),
        (RELEVANCE_6, "N/A"),
    )


# Define a set of choices for the Likelihood


class LikelihoodChoices(ChoiceSet):

    LIKELIHOOD_1 = "Very High"
    LIKELIHOOD_2 = "High"
    LIKELIHOOD_3 = "Moderate"
    LIKELIHOOD_4 = "Low"
    LIKELIHOOD_5 = "Very Low"

    # Beszédes álnevek
    VERY_HIGH = LIKELIHOOD_1
    HIGH = LIKELIHOOD_2
    MODERATE = LIKELIHOOD_3
    MEDIUM = LIKELIHOOD_3
    LOW = LIKELIHOOD_4
    VERY_LOW = LIKELIHOOD_5

    CHOICES = (
        (LIKELIHOOD_1, "Very High"),
        (LIKELIHOOD_2, "High"),
        (LIKELIHOOD_3, "Moderate"),
        (LIKELIHOOD_4, "Low"),
        (LIKELIHOOD_5, "Very Low"),
    )


# Define a set of choices for the Impact


class ImpactChoices(ChoiceSet):

    IMPACT_1 = "Very High"
    IMPACT_2 = "High"
    IMPACT_3 = "Moderate"
    IMPACT_4 = "Low"
    IMPACT_5 = "Very Low"

    # Beszédes álnevek
    VERY_HIGH = IMPACT_1
    HIGH = IMPACT_2
    MODERATE = IMPACT_3
    MEDIUM = IMPACT_3
    LOW = IMPACT_4
    VERY_LOW = IMPACT_5

    CHOICES = (
        (IMPACT_1, "Very High"),
        (IMPACT_2, "High"),
        (IMPACT_3, "Moderate"),
        (IMPACT_4, "Low"),
        (IMPACT_5, "Very Low"),
    )


# Define Asset Type Choices

AssetTypes = Q(
    Q(app_label="dcim", model="device")
    | Q(app_label="virtualization", model="virtualmachine")
)

# Define Level of Risk Choices


class RiskLevelChoices(ChoiceSet):

    RISK_LEVEL_1 = "Very High"
    RISK_LEVEL_2 = "High"
    RISK_LEVEL_3 = "Moderate"
    RISK_LEVEL_4 = "Low"
    RISK_LEVEL_5 = "Very Low"

    CHOICES = (
        (RISK_LEVEL_1, "Very High"),
        (RISK_LEVEL_2, "High"),
        (RISK_LEVEL_3, "Moderate"),
        (RISK_LEVEL_4, "Low"),
        (RISK_LEVEL_5, "Very Low"),
    )


# Define CVE part choices


class CVE_PART_CHOICES(ChoiceSet):

    PART_1 = "a"
    PART_2 = "o"
    PART_3 = "h"

    CHOICES = (
        (PART_1, "Applications"),
        (PART_2, "Operating Systems"),
        (PART_3, "Hardware Devices"),
    )

# ControlCategoryChoices

class ControlCategoryChoices(ChoiceSet):

    CATEGORY_1 = "Preventive"
    CATEGORY_2 = "Detective"

    CHOICES = (
        (CATEGORY_1, "Preventive"),
        (CATEGORY_2, "Detective"),
    )
