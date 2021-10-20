# Copyright 2021 Canonical
# See LICENSE file for licensing details.

import base64
import itertools
import json
import unittest
from unittest import mock

import gitlab
from ops import model
from ops import testing as ops_testing

import charm


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = ops_testing.Harness(charm.LegendGitlabIntegratorCharm)
        self.addCleanup(self.harness.cleanup)

    def test_get_gitlab_scheme(self):
        self.harness.begin()
        for scheme in charm.VALID_GITLAB_SCHEMES:
            self.harness.update_config({"api-scheme": scheme})
            self.assertEqual(self.harness.charm._get_gitlab_scheme(), scheme)
        with self.assertRaises(ValueError):
            self.harness.update_config({"api-scheme": "ssh"})
            self.harness.charm._get_gitlab_scheme()

    def _add_relation(self, relation_name, relation_data):
        """Adds a relation with the given name and data."""
        relator_name = "%s-relator" % relation_name
        rel_id = self.harness.add_relation(relation_name, relator_name)
        self.harness.add_relation_unit(rel_id, relator_name)
        self.harness.update_relation_data(rel_id, relator_name, relation_data)
        return rel_id

    def _add_legend_relations(self, check_statuses=True):
        """Adds all the required relations to the Legend services."""
        rels = {}
        for i, relation_name in enumerate(charm.ALL_LEGEND_RELATION_NAMES):
            if check_statuses:
                self.assertIsInstance(self.harness.charm.unit.status, model.BlockedStatus)
                self.assertEqual(
                    self.harness.charm.unit.status.message,
                    "missing following legend relations: %s"
                    % (", ".join(charm.ALL_LEGEND_RELATION_NAMES[i:])),
                )
            rels[relation_name] = self._add_relation(
                relation_name,
                {"legend-gitlab-redirect-uris": json.dumps(["%s-redirect-uri" % relation_name])},
            )
            self.harness.update_config()
        return rels

    def _get_gitlab_creds_from_config(self, config, client_id=None, client_secret=None, cert=None):
        creds = {
            "gitlab_host": config["gitlab-host"],
            "gitlab_port": config["gitlab-port"],
            "gitlab_scheme": config["api-scheme"],
            "client_id": config.get("bypass-client-id", client_id),
            "client_secret": config.get("bypass-client-secret", client_secret),
            "openid_discovery_url": (
                charm.GITLAB_OPENID_DISCOVERY_URL_FORMAT
                % {
                    "base_url": charm.GITLAB_BASE_URL_FORMAT
                    % {
                        "scheme": config["api-scheme"],
                        "host": config["gitlab-host"],
                        "port": config["gitlab-port"],
                    }
                }
            ),
        }
        if cert:
            creds["gitlab_host_cert_b64"] = base64.b64encode(cert).decode()
        return creds

    @mock.patch("charm.ssl")
    @mock.patch(
        "charms.finos_legend_gitlab_integrator_k8s.v0.legend_gitlab.set_legend_gitlab_creds_in_relation_data"
    )
    def test_charm_setup_gitlab_bypass(self, _set_legend_creds_mock, _mock_ssl):
        _mock_ssl.get_server_certificate.return_value = b"test_cert_pem"
        _mock_ssl.PEM_cert_to_DER_cert.return_value = b"test_cert_der"

        self.harness.begin_with_initial_hooks()

        # Add all the service relations:
        legend_relations_id_map = self._add_legend_relations()

        # Check charm is requesting GitLab creds:
        self.assertIsInstance(self.harness.charm.unit.status, model.BlockedStatus)
        self.assertEqual(
            self.harness.charm.unit.status.message,
            "awaiting gitlab server configuration or relation",
        )

        # Give it bypass creds for GitLab:
        config_values = {
            "gitlab-host": "gitlab_host",
            "api-scheme": "https",
            "gitlab-port": 1234,
            "bypass-client-id": "test_client_id",
            "bypass-client-secret": "test_client_secret",
        }
        self.harness.update_config(config_values)
        self.assertIsInstance(self.harness.charm.unit.status, model.ActiveStatus)
        self.assertEqual(
            self.harness.charm._stored.gitlab_client_id, config_values["bypass-client-id"]
        )
        self.assertEqual(
            self.harness.charm._stored.gitlab_client_secret, config_values["bypass-client-secret"]
        )

        # Check relations data:
        creds = self._get_gitlab_creds_from_config(
            config_values, cert=_mock_ssl.PEM_cert_to_DER_cert.return_value
        )
        relations_set_calls = []
        for relation_name, relation_id in legend_relations_id_map.items():
            relations_set_calls.append(mock.call({}, creds, validate_creds=False))
        _set_legend_creds_mock.assert_has_calls(relations_set_calls)

    @mock.patch("charm.ssl")
    @mock.patch("gitlab.Gitlab")
    @mock.patch(
        "charms.finos_legend_gitlab_integrator_k8s.v0.legend_gitlab.set_legend_gitlab_creds_in_relation_data"
    )
    def test_charm_setup_gitlab_application(
        self, _set_legend_creds_mock, _mock_gitlab_cls, _mock_ssl
    ):
        _mock_gitlab = mock.MagicMock()
        _mock_gitlab.applications.list.return_value = []
        _mock_app = mock.MagicMock()
        _mock_app.application_name = "test_app_name"
        _mock_app.application_id = "test_app_id"
        _mock_app.secret = "test_app_secret"
        _mock_gitlab.applications.create.return_value = _mock_app
        test_cert_pem = b"test_cert_pem"
        _mock_ssl.get_server_certificate.return_value = test_cert_pem
        test_cert_der = b"test_cert_der"
        _mock_ssl.PEM_cert_to_DER_cert.return_value = test_cert_der

        _mock_gitlab_cls.return_value = _mock_gitlab
        self.harness.begin_with_initial_hooks()

        # Add all the service relations:
        legend_relations_id_map = self._add_legend_relations()

        # Check charm is requesting GitLab creds:
        self.assertIsInstance(self.harness.charm.unit.status, model.BlockedStatus)
        self.assertEqual(
            self.harness.charm.unit.status.message,
            "awaiting gitlab server configuration or relation",
        )
        _mock_gitlab.applications.list.assert_not_called()
        _mock_gitlab.applications.create.assert_not_called()
        _mock_ssl.get_server_certificate.assert_not_called()
        _mock_ssl.PEM_cert_to_DER_cert.assert_not_called()

        # Configure for private gitlab:
        config = {
            "application-name": _mock_app.application_name,
            "gitlab-host": "gitlab_host",
            "api-scheme": "https",
            "gitlab-port": 1234,
            "access-token": "gitlab-token",
        }

        # Test auth failure:
        _mock_gitlab.applications.list.side_effect = gitlab.exceptions.GitlabAuthenticationError
        self.harness.update_config(config)
        self.assertIsInstance(self.harness.charm.unit.status, model.BlockedStatus)
        _mock_gitlab.applications.list.assert_called_once()
        self.assertEqual(
            self.harness.charm.unit.status.message,
            "failed to authorize against gitlab, are the credentials correct?",
        )
        _mock_gitlab.applications.create.assert_not_called()
        _mock_ssl.get_server_certificate.assert_not_called()
        _mock_ssl.PEM_cert_to_DER_cert.assert_not_called()

        # Test GitLab applications APIs not being available (HTTP 403):
        _mock_gitlab.applications.list.reset_mock()
        _mock_gitlab.applications.list.side_effect = gitlab.exceptions.GitlabError(
            "irrelevant", 403
        )
        self.harness.update_config(config)
        self.assertIsInstance(self.harness.charm.unit.status, model.BlockedStatus)
        _mock_gitlab.applications.list.assert_called_once()
        self.assertEqual(
            self.harness.charm.unit.status.message,
            "gitlab refused access to the applications apis with a 403"
            ", ensure the configured gitlab host can create "
            "application or manuallly create one",
        )
        _mock_gitlab.applications.create.assert_not_called()
        _mock_ssl.get_server_certificate.assert_not_called()
        _mock_ssl.PEM_cert_to_DER_cert.assert_not_called()

        # Test any other gitlab applications API error:
        # List failing:
        _mock_gitlab.applications.list.reset_mock()
        _mock_gitlab.applications.list.side_effect = Exception
        self.harness.update_config(config)
        self.assertIsInstance(self.harness.charm.unit.status, model.BlockedStatus)
        _mock_gitlab.applications.list.assert_called_once()
        self.assertEqual(self.harness.charm.unit.status.message, "failed to access gitlab api")

        # Test application already exists:
        _mock_gitlab.applications.list.reset_mock()
        _mock_gitlab.applications.list.side_effect = None
        _mock_gitlab.applications.list.return_value = [_mock_app]
        self.harness.update_config()
        self.assertIsInstance(self.harness.charm.unit.status, model.BlockedStatus)
        _mock_gitlab.applications.list.assert_called_once()
        self.assertEqual(
            self.harness.charm.unit.status.message,
            "application with name '%s' already exists on GitLab, please review the charm "
            "documentation on dealing with this" % _mock_app.application_name,
        )

        # `Gitlab.applications.create() failing:`
        _mock_gitlab.applications.list.reset_mock()
        _mock_gitlab.applications.list.side_effect = None
        _mock_gitlab.applications.list.return_value = []
        _mock_gitlab.applications.create.side_effect = Exception
        self.harness.update_config(config)
        self.assertIsInstance(self.harness.charm.unit.status, model.BlockedStatus)
        _mock_gitlab.applications.list.assert_called_once()
        self.assertEqual(
            self.harness.charm.unit.status.message, "failed to create application on gitlab"
        )

        # `ssl.get_server_certificate` on GitLab failing:
        _mock_gitlab.applications.list.reset_mock()
        _mock_gitlab.applications.list.side_effect = None
        _mock_gitlab.applications.list.return_value = []
        _mock_gitlab.applications.create.return_value = _mock_app
        _mock_gitlab.applications.create.side_effect = None
        _mock_ssl.get_server_certificate.side_effect = Exception
        self.harness.update_config(config)
        self.assertIsInstance(self.harness.charm.unit.status, model.BlockedStatus)
        _mock_gitlab.applications.list.assert_called_once()
        _mock_ssl.get_server_certificate.assert_called_once_with(
            (config["gitlab-host"], config["gitlab-port"])
        )
        self.assertEqual(
            self.harness.charm.unit.status.message,
            "failed to retrieve SSL cert for GitLab host '%s:%d'. SSL is required "
            "for the GitLab to be usable by the Legend components"
            % (config["gitlab-host"], config["gitlab-port"]),
        )

        # Actually let it run:
        _mock_gitlab.applications.list.reset_mock()
        _mock_gitlab.applications.list.side_effect = None
        _mock_gitlab.applications.create.reset_mock()
        _mock_gitlab.applications.create.side_effect = None
        _mock_ssl.get_server_certificate.reset_mock()
        _mock_ssl.get_server_certificate.side_effect = None
        _mock_ssl.get_server_certificate.return_value = test_cert_pem
        _mock_ssl.PEM_cert_to_DER_cert.reset_mock()
        _mock_ssl.PEM_cert_to_DER_cert.side_effect = None
        _mock_ssl.PEM_cert_to_DER_cert.return_value = test_cert_der

        self.harness.update_config(config)
        self.assertIsInstance(self.harness.charm.unit.status, model.ActiveStatus)
        self.assertEqual(self.harness.charm._stored.gitlab_client_id, _mock_app.application_id)
        self.assertEqual(self.harness.charm._stored.gitlab_client_secret, _mock_app.secret)
        _mock_gitlab.applications.list.assert_called_once()
        _mock_gitlab.applications.create.assert_called_once_with(
            {
                "name": config["application-name"],
                "scopes": " ".join(charm.GITLAB_REQUIRED_SCOPES),
                "redirect_uri": "\n".join(
                    [
                        "%s-redirect-uri" % rel
                        for rel in [
                            # NOTE: ordering is important here:
                            charm.RELATION_NAME_ENGINE,
                            charm.RELATION_NAME_SDLC,
                            charm.RELATION_NAME_STUDIO,
                        ]
                    ]
                ),
            }
        )
        _mock_ssl.get_server_certificate.assert_called_once_with(
            (config["gitlab-host"], config["gitlab-port"])
        )
        _mock_ssl.PEM_cert_to_DER_cert.assert_called_once_with(test_cert_pem)

        # Check relations data:
        creds = self._get_gitlab_creds_from_config(
            config,
            client_id=_mock_app.application_id,
            client_secret=_mock_app.secret,
            cert=_mock_ssl.PEM_cert_to_DER_cert.return_value,
        )
        relations_set_calls = []
        for relation_name, relation_id in legend_relations_id_map.items():
            relations_set_calls.append(mock.call({}, creds, validate_creds=False))
        _set_legend_creds_mock.assert_has_calls(relations_set_calls)

    @mock.patch(
        "charms.finos_legend_gitlab_integrator_k8s.v0.legend_gitlab.set_legend_gitlab_creds_in_relation_data"
    )
    def test_get_redirect_uris_action(self, _set_legend_creds_mock):
        self.harness.begin_with_initial_hooks()

        # NOTE: ordering is important:
        relations = [
            charm.RELATION_NAME_ENGINE,
            charm.RELATION_NAME_SDLC,
            charm.RELATION_NAME_STUDIO,
        ]
        relation_redirect_urls_map = {
            relation_name: ["%s-redirect-uri" % relation_name] for relation_name in relations
        }
        for relation in relations:
            # Action should be unusable without all relations:
            with self.assertRaises(ValueError):
                self.harness.charm._on_get_redirect_uris_actions(mock.MagicMock())
            self._add_relation(
                relation,
                {"legend-gitlab-redirect-uris": json.dumps(relation_redirect_urls_map[relation])},
            )
            self.harness.update_config({})

        # After all the relations are added, we should be able to retrieve the  URIs:
        expected = "\n".join(
            list(itertools.chain(*[relation_redirect_urls_map[rel] for rel in relations]))
        )
        event = mock.Mock()
        self.harness.charm._on_get_redirect_uris_actions(event)
        event.set_results.assert_called_once_with({"result": expected})
