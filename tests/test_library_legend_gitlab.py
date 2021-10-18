# Copyright 2021 Canonical
# See LICENSE file for licensing details.

import json
import unittest
from unittest import mock

from charms.finos_legend_gitlab_integrator_k8s.v0 import legend_gitlab
from ops import charm as ops_charm
from ops import testing as ops_testing

TEST_GITLAB_RELATION_NAME = "legend-gitlab"


class LegendDBConsumerTestCharm(ops_charm.CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.legend_gitlab_consumer = legend_gitlab.LegendGitlabConsumer(
            self, TEST_GITLAB_RELATION_NAME
        )


class TestLegendDBConsumer(unittest.TestCase):
    def setUp(self):
        self.harness = ops_testing.Harness(
            LegendDBConsumerTestCharm,
            meta="""
            name: legend-gitlab-test
            requires:
              %s:
                interface: legend_test_gitlab
        """
            % TEST_GITLAB_RELATION_NAME,
        )
        self.addCleanup(self.harness.cleanup)

    def _add_gitlab_relation(self, relator_name, relation_data):
        rel_id = self.harness.add_relation(TEST_GITLAB_RELATION_NAME, relator_name)
        self.harness.add_relation_unit(rel_id, relator_name)
        self.harness.update_relation_data(rel_id, relator_name, relation_data)
        return rel_id

    def test_validate_legend_gitlab_credentials(self):
        bad_inputs = [
            # Basic cases:
            None,
            True,
            13,
            "str",
            {},
            # Partial:
            {"client_id": "test"},
            {"client_secret": "test"},
            # All keys but some unset values:
            {
                "client_id": "test_id",
                "client_secret": None,
                "openid_discovery_url": "test_discovery_url",
                "gitlab_host": "test_host",
                "gitlab_port": 7667,
                "gitlab_scheme": None,
                "gitlab_host_cert_b64": "test_cert",
            },
            # All keys with some wrongly-typed string params:
            {
                "client_id": 13,
                "client_secret": ["test_list_elem_1"],
                "openid_discovery_url": "test_discovery_url",
                "gitlab_host": "test_host",
                "gitlab_port": 7667,
                "gitlab_scheme": 3.14,
                "gitlab_host_cert_b64": "test_cert",
            },
            # All keys but port parameter is mistyped:
            {
                "client_id": "test_id",
                "client_secret": "test_secret",
                "openid_discovery_url": "test_discovery_url",
                "gitlab_host": "test_host",
                "gitlab_port": "test_should_be_an_int",
                "gitlab_scheme": "https",
                "gitlab_host_cert_b64": "test_cert",
            },
        ]
        for bad in bad_inputs:
            with self.assertRaises(ValueError):
                legend_gitlab._validate_legend_gitlab_credentials(bad)

        good_inputs = [
            {
                # Gitlab host cert being empty should be acceptable:
                "client_id": "test_id",
                "client_secret": "test_secret",
                "openid_discovery_url": "test_discovery_url",
                "gitlab_host": "test_host",
                "gitlab_port": 7667,
                "gitlab_scheme": "https",
                "gitlab_host_cert_b64": "",
            },
            {
                "client_id": "test_id",
                "client_secret": "test_secret",
                "openid_discovery_url": "test_discovery_url",
                "gitlab_host": "test_host",
                "gitlab_port": 7667,
                "gitlab_scheme": "https",
                "gitlab_host_cert_b64": "test_cert",
            },
        ]
        for good in good_inputs:
            self.assertTrue(legend_gitlab._validate_legend_gitlab_credentials(good))

    def test__validate_legend_gitlab_redirect_uris(self):
        bad_inputs = [
            # Basic cases:
            None,
            True,
            13,
            "str",
            {},
            # Lists of improper things:,
            ["list1", None],
            ["list2", 13],
            ["list3", {}],
        ]
        for bad in bad_inputs:
            with self.assertRaises(ValueError):
                legend_gitlab._validate_legend_gitlab_redirect_uris(bad)

        good_inputs = [[], ["uri1"], ["uri1", "uri2", "uri3"]]
        for good in good_inputs:
            self.assertTrue(legend_gitlab._validate_legend_gitlab_redirect_uris(good))

    @mock.patch(
        "charms.finos_legend_gitlab_integrator_k8s.v0.legend_gitlab._validate_legend_gitlab_credentials"
    )
    def test_set_legend_gitlab_creds_in_relation_data(self, _validate_creds_mock):
        test_creds = {"test": "credentials"}
        test_rel_data = {}
        self.assertTrue(
            legend_gitlab.set_legend_gitlab_creds_in_relation_data(
                test_rel_data, test_creds, validate_creds=True
            )
        )
        _validate_creds_mock.assert_called_once_with(test_creds)

        # Check bad creds:
        _validate_creds_mock.reset_mock()
        _validate_creds_mock.side_effect = ValueError
        with self.assertRaises(ValueError):
            legend_gitlab.set_legend_gitlab_creds_in_relation_data(
                test_rel_data, test_creds, validate_creds=True
            )
        _validate_creds_mock.assert_called_once_with(test_creds)

        # Ensure doesn't re-raise if told not to:
        _validate_creds_mock.reset_mock()
        _validate_creds_mock.side_effect = ValueError
        self.assertTrue(
            legend_gitlab.set_legend_gitlab_creds_in_relation_data(
                test_rel_data, test_creds, validate_creds=False
            )
        )
        _validate_creds_mock.assert_called_once_with(test_creds)

    @mock.patch(
        "charms.finos_legend_gitlab_integrator_k8s.v0.legend_gitlab._validate_legend_gitlab_redirect_uris"
    )
    def test_set_legend_gitlab_redirect_uris_in_relation_data(self, _validate_uris_mock):
        test_uris = ["uri1", "uri2"]
        test_rel_data = {}
        self.assertTrue(
            legend_gitlab.set_legend_gitlab_redirect_uris_in_relation_data(
                test_rel_data, test_uris
            )
        )
        _validate_uris_mock.assert_called_once_with(test_uris)

        # Check bad creds:
        _validate_uris_mock.reset_mock()
        _validate_uris_mock.side_effect = ValueError
        with self.assertRaises(ValueError):
            legend_gitlab.set_legend_gitlab_redirect_uris_in_relation_data(
                test_rel_data, test_uris
            )
        _validate_uris_mock.assert_called_once_with(test_uris)

    @mock.patch(
        "charms.finos_legend_gitlab_integrator_k8s.v0.legend_gitlab._validate_legend_gitlab_credentials"
    )
    def test_get_legend_gitlab_creds(self, _validate_creds_mock):
        self.harness.begin_with_initial_hooks()

        # Should not return anything as it is not related yet:
        self.assertEqual(
            self.harness.charm.legend_gitlab_consumer.get_legend_gitlab_creds(None), {}
        )
        _validate_creds_mock.assert_not_called()

        # Add a relation with no relation data:
        related_app_name = "test_relator"
        rel_id = self._add_gitlab_relation(related_app_name, {})
        self.assertEqual(
            self.harness.charm.legend_gitlab_consumer.get_legend_gitlab_creds(rel_id), {}
        )
        _validate_creds_mock.assert_not_called()

        # Misformatted relation data:
        self.harness.update_relation_data(
            rel_id, related_app_name, {"legend-gitlab-connection": "<malformed JSON>"}
        )
        self.harness.update_config()
        _validate_creds_mock.assert_not_called()
        with self.assertRaises(ValueError):
            self.harness.charm.legend_gitlab_consumer.get_legend_gitlab_creds(rel_id)

        # Invalid creds (which will get echoed back since the validation was mocked):
        bad_relation_data = {"not": "correct"}
        self.harness.update_relation_data(
            rel_id, related_app_name, {"legend-gitlab-connection": json.dumps(bad_relation_data)}
        )
        self.assertEqual(
            self.harness.charm.legend_gitlab_consumer.get_legend_gitlab_creds(rel_id),
            bad_relation_data,
        )
        _validate_creds_mock.assert_called_once_with(bad_relation_data)

    @mock.patch(
        "charms.finos_legend_gitlab_integrator_k8s.v0.legend_gitlab._validate_legend_gitlab_redirect_uris"
    )
    def test_get_legend_redirect_uris(self, _validate_uris_mock):
        self.harness.begin_with_initial_hooks()

        # Should not return anything as it is not related yet:
        self.assertEqual(
            self.harness.charm.legend_gitlab_consumer.get_legend_redirect_uris(None), []
        )
        _validate_uris_mock.assert_not_called()

        # Add a relation with no relation data:
        related_app_name = "test_relator"
        rel_id = self._add_gitlab_relation(related_app_name, {})
        self.assertEqual(
            self.harness.charm.legend_gitlab_consumer.get_legend_redirect_uris(rel_id), []
        )
        _validate_uris_mock.assert_not_called()

        # Misformatted relation data:
        self.harness.update_relation_data(
            rel_id, related_app_name, {"legend-gitlab-redirect-uris": "<malformed JSON>"}
        )
        self.harness.update_config()
        _validate_uris_mock.assert_not_called()
        with self.assertRaises(ValueError):
            self.harness.charm.legend_gitlab_consumer.get_legend_redirect_uris(rel_id)

        # Proper test:
        redirect_uris = ["uri1", "uri2", "uri3"]
        self.harness.update_relation_data(
            rel_id, related_app_name, {"legend-gitlab-redirect-uris": json.dumps(redirect_uris)}
        )
        self.harness.update_config()
        self.assertEqual(
            self.harness.charm.legend_gitlab_consumer.get_legend_redirect_uris(rel_id),
            redirect_uris,
        )
        _validate_uris_mock.assert_called_once_with(redirect_uris)
