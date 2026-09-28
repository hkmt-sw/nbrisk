"""
View tests for nb_risk.

Tests cover: list, detail, add, edit, and delete views for all models.
Uses NetBox's test client with authentication.
"""

from django.test import TestCase, Client
from django.urls import reverse

from users.models import User
from dcim.models import Platform

from nb_risk.models import (
    ThreatSource,
    Vulnerability,
    Risk,
    Control,
    CPEMapping,
    ThreatEvent,
)
from nb_risk.choices import (
    ThreatTypeChoices,
    CapabilityChoices,
    RelevanceChoices,
    LikelihoodChoices,
)


class BaseViewTestCase(TestCase):

    def setUp(self):
        self.user = User.objects.create_superuser(
            username='viewtestuser',
            password='testpassword',
        )
        self.client = Client()
        self.client.force_login(self.user)


class ThreatSourceViewTestCase(BaseViewTestCase):

    def setUp(self):
        super().setUp()
        self.ts = ThreatSource.objects.create(
            name='View Test Source',
            threat_type=ThreatTypeChoices.ADVERSARIAL,
            capability=CapabilityChoices.HIGH,
        )

    def test_list_view(self):
        url = reverse('plugins:nb_risk:threatsource_list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'View Test Source')

    def test_detail_view(self):
        url = reverse('plugins:nb_risk:threatsource', kwargs={'pk': self.ts.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_add_view_get(self):
        url = reverse('plugins:nb_risk:threatsource_add')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_add_view_post(self):
        url = reverse('plugins:nb_risk:threatsource_add')
        data = {
            'name': 'Created Source',
            'threat_type': ThreatTypeChoices.ACCIDENTAL,
            'capability': CapabilityChoices.LOW,
        }
        response = self.client.post(url, data)
        self.assertEqual(ThreatSource.objects.filter(name='Created Source').count(), 1)

    def test_delete_view(self):
        url = reverse('plugins:nb_risk:threatsource_delete', kwargs={'pk': self.ts.pk})
        response = self.client.post(url, {'confirm': True})
        self.assertEqual(ThreatSource.objects.count(), 0)


class VulnerabilityViewTestCase(BaseViewTestCase):

    def setUp(self):
        super().setUp()
        self.vuln = Vulnerability.objects.create(
            name='CVE-2021-44228',
            cve='CVE-2021-44228',
        )

    def test_list_view(self):
        url = reverse('plugins:nb_risk:vulnerability_list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'CVE-2021-44228')

    def test_detail_view(self):
        url = reverse('plugins:nb_risk:vulnerability', kwargs={'pk': self.vuln.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_search_view(self):
        url = reverse('plugins:nb_risk:vulnerability_search')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)


class CPEMappingViewTestCase(BaseViewTestCase):

    def setUp(self):
        super().setUp()
        self.platform = Platform.objects.create(name='NX-OS', slug='nx-os')
        self.mapping = CPEMapping.objects.create(
            platform=self.platform,
            cpe_part='o',
            cpe_vendor='cisco',
            cpe_product='nx-os',
        )

    def test_list_view(self):
        url = reverse('plugins:nb_risk:cpemapping_list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'cisco')

    def test_detail_view(self):
        url = reverse('plugins:nb_risk:cpemapping', kwargs={'pk': self.mapping.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_add_view_get(self):
        url = reverse('plugins:nb_risk:cpemapping_add')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_cpe_lookup_view(self):
        url = reverse('plugins:nb_risk:cpe_lookup')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_delete_view(self):
        url = reverse('plugins:nb_risk:cpemapping_delete', kwargs={'pk': self.mapping.pk})
        response = self.client.post(url, {'confirm': True})
        self.assertEqual(CPEMapping.objects.count(), 0)


class ControlViewTestCase(BaseViewTestCase):

    def setUp(self):
        super().setUp()
        self.control = Control.objects.create(name='Test Control')

    def test_list_view(self):
        url = reverse('plugins:nb_risk:control_list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_detail_view(self):
        url = reverse('plugins:nb_risk:control', kwargs={'pk': self.control.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)


class VulnerabilityAssignmentEditViewTestCase(TestCase):
    """The add view only accepts supported assets the user may view, and takes the asset from the query string."""

    @classmethod
    def setUpTestData(cls):
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site

        site = Site.objects.create(name='Site 1', slug='site-1')
        manufacturer = Manufacturer.objects.create(name='Manufacturer 1', slug='manufacturer-1')
        device_type = DeviceType.objects.create(manufacturer=manufacturer, model='Model 1', slug='model-1')
        role = DeviceRole.objects.create(name='Role 1', slug='role-1')
        cls.site = site
        cls.visible = Device.objects.create(name='Visible', device_type=device_type, role=role, site=site)
        cls.hidden = Device.objects.create(name='Hidden', device_type=device_type, role=role, site=site)
        cls.vulnerability = Vulnerability.objects.create(name='Vulnerability 1', cve='CVE-2021-1234')

    def setUp(self):
        from core.models import ObjectType
        from dcim.models import Device
        from users.models import ObjectPermission
        from nb_risk.models import VulnerabilityAssignment

        self.user = User.objects.create_user(username='assignmentuser', password='testpassword')
        add = ObjectPermission.objects.create(name='Add assignments', actions=['add', 'view'])
        add.object_types.add(ObjectType.objects.get_for_model(VulnerabilityAssignment))
        add.users.add(self.user)
        view = ObjectPermission.objects.create(
            name='View one device', actions=['view'], constraints={'name': 'Visible'}
        )
        view.object_types.add(ObjectType.objects.get_for_model(Device))
        view.users.add(self.user)
        vulns = ObjectPermission.objects.create(name='View vulnerabilities', actions=['view'])
        vulns.object_types.add(ObjectType.objects.get_for_model(Vulnerability))
        vulns.users.add(self.user)
        self.client = Client()
        self.client.force_login(self.user)
        self.device_ct = ObjectType.objects.get_for_model(Device).pk

    def _url(self, object_type, asset_id):
        return (reverse('plugins:nb_risk:vulnerabilityassignment_add')
                + f'?asset_object_type={object_type}&asset_id={asset_id}')

    def test_add_view_visible_asset(self):
        response = self.client.get(self._url(self.device_ct, self.visible.pk))
        self.assertEqual(response.status_code, 200)

    def test_add_view_hidden_asset_returns_404(self):
        response = self.client.get(self._url(self.device_ct, self.hidden.pk))
        self.assertEqual(response.status_code, 404)

    def test_add_view_unsupported_type_returns_404(self):
        from core.models import ObjectType
        from dcim.models import Manufacturer
        from users.models import ObjectPermission

        perm = ObjectPermission.objects.create(name='View manufacturers', actions=['view'])
        perm.object_types.add(ObjectType.objects.get_for_model(Manufacturer))
        perm.users.add(self.user)
        manufacturer = Manufacturer.objects.first()
        response = self.client.get(self._url(ObjectType.objects.get_for_model(Manufacturer).pk, manufacturer.pk))
        self.assertEqual(response.status_code, 404)

    def test_add_view_configured_site_asset(self):
        # dcim.site is in the default supported_assets, so its "Add Vulnerability" button must work
        from core.models import ObjectType
        from dcim.models import Site
        from users.models import ObjectPermission

        perm = ObjectPermission.objects.create(name='View sites', actions=['view'])
        perm.object_types.add(ObjectType.objects.get_for_model(Site))
        perm.users.add(self.user)
        response = self.client.get(self._url(ObjectType.objects.get_for_model(Site).pk, self.site.pk))
        self.assertEqual(response.status_code, 200)

    def test_post_body_cannot_override_asset(self):
        from nb_risk.models import VulnerabilityAssignment

        response = self.client.post(self._url(self.device_ct, self.visible.pk), {
            'vulnerability': self.vulnerability.pk,
            'asset_object_type': self.device_ct,
            'asset_id': self.hidden.pk,
        })
        self.assertIn(response.status_code, (200, 302))
        self.assertFalse(VulnerabilityAssignment.objects.filter(asset_id=self.hidden.pk).exists())
        self.assertTrue(VulnerabilityAssignment.objects.filter(asset_id=self.visible.pk).exists())
