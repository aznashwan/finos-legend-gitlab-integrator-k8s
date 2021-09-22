#!/usr/bin/env python3
# Copyright 2021 Canonical
# See LICENSE file for licensing details.

""" Module defining a Charm providing GitLab integration for FINOS Legend. """

import logging

import gitlab

from ops import charm
from ops import framework
from ops import main
from ops import model

from charms.finos_legend_gitlab_integrator_k8s.v0 import legend_gitlab


logger = logging.getLogger(__name__)

GITLAB_BASE_URL_FORMAT = "%(scheme)s://%(host)s:%(port)s"
GITLAB_SCHEME_HTTP = "http"
GITLAB_SCHEME_HTTPS = "https"
VALID_GITLAB_SCHEMES = [GITLAB_SCHEME_HTTP, GITLAB_SCHEME_HTTPS]

# TODO(aznashwan): consider making these configurable for people using LDAP
# https://gist.github.com/gpocentek/bd4c3fbf8a6ce226ebddc4aad6b46c0a
GITLAB_LOGIN_URL_FORMAT = "%(base_url)s/users/sign_in"
GITLAB_SIGNIN_URL_FORMAT = "%(base_url)s/users/sign_in"

GITLAB_OPENID_DISCOVERY_URL_FORMAT = (
    "%(base_url)s/.well-known/openid-configuration")

GITLAB_REQUIRED_SCOPES = ['api', 'openid', 'profile']


class LegendGitlabIntegratorCharm(charm.CharmBase):
    """Charm class which provides GitLab access to other Legend charms."""

    _stored = framework.StoredState()

    def __init__(self, *args):
        super().__init__(*args)

        self._set_stored_defaults()

        # General hooks:
        self.framework.observe(self.on.install, self._on_install)

        # TODO(aznashwan): register eventual GitLab relation hooks:
        # self.framework.observe(
        #     self.on["gitlab"].relation_joined,
        #     self._on_gitlab_relation_joined)
        # self.framework.observe(
        #     self.on["gitlab"].relation_changed,
        #     self._on_gitlab_relation_changed)

        # Legend component relation events:
        self.framework.observe(
            self.on["legend-sdlc-gitlab"].relation_joined,
            self._on_legend_sdlc_gitlab_relation_joined)
        self.framework.observe(
            self.on["legend-sdlc-gitlab"].relation_changed,
            self._on_legend_sdlc_gitlab_relation_changed)
        self.framework.observe(
            self.on["legend-sdlc-gitlab"].relation_broken,
            self._on_legend_sdlc_gitlab_relation_broken)

        self._legend_gitlab_sdlc_consumer = (
            legend_gitlab.LegendGitlabConsumer(
                self, relation_name='legend-sdlc-gitlab'))

        self.framework.observe(
            self.on["legend-engine-gitlab"].relation_joined,
            self._on_legend_engine_gitlab_relation_joined)
        self.framework.observe(
            self.on["legend-engine-gitlab"].relation_changed,
            self._on_legend_engine_gitlab_relation_changed)
        self.framework.observe(
            self.on["legend-engine-gitlab"].relation_broken,
            self._on_legend_engine_gitlab_relation_broken)
        self._legend_gitlab_engine_consumer = (
            legend_gitlab.LegendGitlabConsumer(
                self, relation_name='legend-engine-gitlab'))

        self.framework.observe(
            self.on["legend-studio-gitlab"].relation_joined,
            self._on_legend_studio_gitlab_relation_joined)
        self.framework.observe(
            self.on["legend-studio-gitlab"].relation_changed,
            self._on_legend_studio_gitlab_relation_changed)
        self.framework.observe(
            self.on["legend-studio-gitlab"].relation_broken,
            self._on_legend_studio_gitlab_relation_broken)
        self._legend_gitlab_studio_consumer = (
            legend_gitlab.LegendGitlabConsumer(
                self, relation_name='legend-studio-gitlab'))

        # Actions:
        self.framework.observe(
            self.on.get_redirect_uris_action,
            self._on_get_redirect_uris_actions)

    def _set_stored_defaults(self) -> None:
        self._stored.set_default(log_level="DEBUG")
        self._stored.set_default(gitlab_client_id="")
        self._stored.set_default(gitlab_client_secret="")
        self._stored.set_default(legend_sdlc_redirect_uris=None)
        self._stored.set_default(legend_engine_redirect_uris=None)
        self._stored.set_default(legend_studio_redirect_uris=None)

    def _on_install(self, event: charm.InstallEvent):
        bypass_client_id = self.model.config['bypass-client-id']
        bypass_client_secret = self.model.config['bypass-client-secret']
        if all([bypass_client_id, bypass_client_secret]):
            logger.info(
                "### Using pre-seeded Gitlab application ID/settings.")
            self._stored.gitlab_client_id = bypass_client_id
            self._stored.gitlab_client_secret = bypass_client_secret
            self._update_charm_status()
            return

        # TODO(aznashwan): attempt to create app on GitLab if not
        raise NotImplementedError("Need bypass ID/secret.")

        self.unit.status = model.BlockedStatus(
            "Awaiting GitLab configuration or relation.")

    def _get_gitlab_scheme(self):
        scheme = self.model.config['api-scheme']
        if scheme not in VALID_GITLAB_SCHEMES:
            raise ValueError(
                "Invalid GitLab scheme '%s'. Must be one of '%s'" % (
                    scheme, VALID_GITLAB_SCHEMES))

        return scheme

    def _get_gitlab_base_url(self):
        return GITLAB_BASE_URL_FORMAT % {
            "scheme": self._get_gitlab_scheme(),
            "host": self.model.config['gitlab-host'],
            "port": self.model.config['gitlab-port']}

    @property
    def _gitlab_client(self):
        return gitlab.Gitlab(
            self._get_gitlab_base_url(),
            private_token=self.model.config['access-token'])

    def _get_gitlab_openid_discovery_url(self):
        return GITLAB_OPENID_DISCOVERY_URL_FORMAT % {
            "base_url": self._get_gitlab_base_url()}

    def _get_gitlab_relation_data(self):
        if not all([
                self._stored.gitlab_client_id,
                self._stored.gitlab_client_secret]):
            logger.warning("GitLab Client ID and Secret unset.")
            return {}
        return {
            "gitlab_host": self.model.config['gitlab-host'],
            "gitlab_port": self.model.config['gitlab-port'],
            "gitlab_scheme": self._get_gitlab_scheme(),
            "client_id": self._stored.gitlab_client_id,
            "client_secret": self._stored.gitlab_client_secret,
            "openid_discovery_url": self._get_gitlab_openid_discovery_url()}

    def _check_gitlab_app_name_available(self, app_name):
        pass

    def _get_legend_services_redirect_uris(self):
        """Returns a string containing the service URLs in the correct order
        (Engine, SDLC, then Studio).
        Returns an empty string if not all Legend services are related.
        """
        service_uris = [
            # NOTE(aznashwan): order of these is important:
            self._stored.legend_engine_redirect_uris,
            self._stored.legend_sdlc_redirect_uris,
            self._stored.legend_studio_redirect_uris]
        # NOTE: it is okay for a service to not have any redirect URIs
        # (i.e. empty string), but not okay for them to not be set (i.e. None):
        if any([item is None for item in service_uris]):
            logger.warning(
                "Missing one or more relations to the Legend "
                "SDLC, Engine, and Studio.")
            return ""

        redirect_uris = "\n".join(service_uris)
        return redirect_uris

    def _update_charm_status(self):
        possible_blocked_status = (
            self._check_legend_services_relations_status())
        if possible_blocked_status is not None:
            self.unit.status = possible_blocked_status
            return
        self.unit.status = model.ActiveStatus()

    def _check_legend_services_relations_status(self):
        """Checks whether all the required Legend services were related.
        Returns None if all the relations are present, or a
        `model.BlockedStatus` with a relevant message otherwise.
        """
        opts = {
            "SDLC": self._stored.legend_sdlc_redirect_uris,
            "Engine": self._stored.legend_engine_redirect_uris,
            "Studio": self._stored.legend_studio_redirect_uris}
        # NOTE(aznashwan): it is acceptable for a service to have no redirect
        # URIs (empty string), but not None:
        missing = [k for k, v in opts.items() if v is None]
        if missing:
            return model.BlockedStatus(
                "Awaiting relations to following legend services: %s" % (
                    ", ".join(missing)))
        return None

    def _create_gitlab_application(self):
        """Creates a GitLab application for the Legend installation.
        Returns a dict with the properties of the newly-created app,
        or an empty dict if there were any issues.
        """
        redirect_uris = self._get_legend_services_redirect_uris()
        if not redirect_uris:
            logger.warning(
                "Cannot create GitLab app without all Legend "
                "services related.")
            return {}

        self._gitlab_client.applications.create({
            # TODO(aznashwan): generate unique app names:
            "name": "Legend Demo",
            "redirect_uri": redirect_uris})
        # TODO(aznashwan): make app trusted:
        # https://github.com/finos/legend/blob/master/installers/docker-compose/legend/scripts/setup-gitlab.sh#L36-L42

    def _on_get_redirect_uris_actions(self, event: charm.ActionEvent):
        redirect_uris = self._get_legend_services_redirect_uris()
        if not redirect_uris:
            raise ValueError(
                "Need to have all Legend services related to return redirect "
                "URIs.")
        event.set_results({"result": redirect_uris})

    def _on_config_changed(self, _) -> None:
        # TODO(aznashwan): presuming config-changed for the actual GitLab host
        # URL, we'll need to:
        # - login to the new gitlab and create the app
        # - notify all related services with the client ID/secret
        pass

    def _on_gitlab_relation_joined(self, event: charm.RelationJoinedEvent):
        # TODO(aznashwan): eventual GitLab operator relation:
        pass

    def _on_gitlab_relation_changed(
            self, event: charm.RelationChangedEvent) -> None:
        # TODO(aznashwan): eventual GitLab operator relation:
        pass

    def _check_set_legend_gitlab_creds_in_relation(
            self, event: charm.RelationChangedEvent):
        """Checks whether all the Legend services have been related before
        setting the GitLab app details in the relation data.
        """
        gitlab_relation_data = self._get_gitlab_relation_data()
        if not gitlab_relation_data:
            logger.info(
                "Not connected to GitLab. (either related, or otherwise), "
                "and thus cannot set relation details.")
            return None

        possible_blocked_status = (
            self._check_legend_services_relations_status())
        if possible_blocked_status:
            # NOTE(aznashwan): we withold sending the GitLab app data
            # until we have all the services related:
            logger.info(
                "Witholding GitLab creds untill all services have registered.")
            event.defer()
            return

        try:
            legend_gitlab.set_legend_gitlab_creds_in_relation_data(
                event.relation.data[self.app], gitlab_relation_data)
        except ValueError as ex:
            logger.warning(
                "Error occurred while setting GitLab creds relation "
                "data: %s" % str(ex))
            self.unit.status = model.BlockedStatus(
                "Failed to set GitLab credentials in relation.")
            return None

        return gitlab_relation_data

    def _on_legend_sdlc_gitlab_relation_joined(
            self, event: charm.RelationJoinedEvent):
        pass

    def _on_legend_sdlc_gitlab_relation_changed(
            self, event: charm.RelationChangedEvent):
        redirect_uris = None
        get_redirect_uris = (
            self._legend_gitlab_sdlc_consumer.get_legend_redirect_uris)

        try:
            redirect_uris = get_redirect_uris(event.relation.id)
        except ValueError:
            self.unit.status = model.BlockedStatus(
                "Failed to read redirect URIs from SDLC relation.")
            return
        if not redirect_uris:
            self.unit.status = model.WaitingStatus(
                "Waiting for SDLC redirect URIs to be set in relation.")
            return

        # NOTE(aznashwan): we pre-join the redirect uris into a string
        # to avoid dealing with StoredList and co.:
        self._stored.legend_sdlc_redirect_uris = "\n".join(redirect_uris)
        self._update_charm_status()

        self._check_set_legend_gitlab_creds_in_relation(event)

    def _on_legend_sdlc_gitlab_relation_broken(
            self, event: charm.RelationBrokenEvent) -> None:
        self._stored.legend_sdlc_redirect_uris = None
        self._update_charm_status()

    def _on_legend_engine_gitlab_relation_joined(
            self, event: charm.RelationJoinedEvent):
        pass

    def _on_legend_engine_gitlab_relation_changed(
            self, event: charm.RelationChangedEvent):
        redirect_uris = None
        get_redirect_uris = (
            self._legend_gitlab_engine_consumer.get_legend_redirect_uris)

        try:
            redirect_uris = get_redirect_uris(event.relation.id)
        except ValueError:
            self.unit.status = model.BlockedStatus(
                "Failed to read redirect URIs from Engine relation.")
            return
        if not redirect_uris:
            self.unit.status = model.WaitingStatus(
                "Waiting for Engine redirect URIs to be set in relation.")
            return

        # NOTE(aznashwan): we pre-join the redirect uris into a string
        # to avoid dealing with StoredList and co.:
        self._stored.legend_engine_redirect_uris = "\n".join(redirect_uris)
        self._update_charm_status()

        self._check_set_legend_gitlab_creds_in_relation(event)

    def _on_legend_engine_gitlab_relation_broken(
            self, event: charm.RelationBrokenEvent) -> None:
        self._stored.legend_engine_redirect_uris = None
        self._update_charm_status()

    def _on_legend_studio_gitlab_relation_joined(
            self, event: charm.RelationJoinedEvent):
        pass

    def _on_legend_studio_gitlab_relation_changed(
            self, event: charm.RelationChangedEvent):
        redirect_uris = None
        get_redirect_uris = (
            self._legend_gitlab_studio_consumer.get_legend_redirect_uris)

        try:
            redirect_uris = get_redirect_uris(event.relation.id)
        except ValueError:
            self.unit.status = model.BlockedStatus(
                "Failed to read redirect URIs from Studio relation.")
            return
        if not redirect_uris:
            self.unit.status = model.WaitingStatus(
                "Waiting for Studio redirect URIs to be set in relation.")
            return

        # NOTE(aznashwan): we pre-join the redirect uris into a string
        # to avoid dealing with StoredList and co.:
        self._stored.legend_studio_redirect_uris = "\n".join(redirect_uris)
        self._update_charm_status()

        self._check_set_legend_gitlab_creds_in_relation(event)

    def _on_legend_studio_gitlab_relation_broken(
            self, event: charm.RelationBrokenEvent) -> None:
        self._stored.legend_studio_redirect_uris = None
        self._update_charm_status()


if __name__ == "__main__":
    main.main(LegendGitlabIntegratorCharm)
