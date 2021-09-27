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

RELATION_NAME_SDLC = "legend-sdlc-gitlab"
RELATION_NAME_ENGINE = "legend-engine-gitlab"
RELATION_NAME_STUDIO = "legend-studio-gitlab"
ALL_LEGEND_RELATION_NAMES = [
    RELATION_NAME_SDLC, RELATION_NAME_ENGINE, RELATION_NAME_STUDIO]


class LegendGitlabIntegratorCharm(charm.CharmBase):
    """Charm class which provides GitLab access to other Legend charms."""

    _stored = framework.StoredState()

    def __init__(self, *args):
        super().__init__(*args)

        self._set_stored_defaults()

        # General hooks:
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(
            self.on.config_changed, self._on_config_changed)

        # TODO(aznashwan): register eventual GitLab relation hooks:
        # self.framework.observe(
        #     self.on["gitlab"].relation_joined,
        #     self._on_gitlab_relation_joined)
        # self.framework.observe(
        #     self.on["gitlab"].relation_changed,
        #     self._on_gitlab_relation_changed)

        # Legend component relation events:
        self.framework.observe(
            self.on[RELATION_NAME_SDLC].relation_joined,
            self._on_legend_sdlc_gitlab_relation_joined)
        self.framework.observe(
            self.on[RELATION_NAME_SDLC].relation_changed,
            self._on_legend_sdlc_gitlab_relation_changed)
        self.framework.observe(
            self.on[RELATION_NAME_SDLC].relation_broken,
            self._on_legend_sdlc_gitlab_relation_broken)

        self.framework.observe(
            self.on[RELATION_NAME_ENGINE].relation_joined,
            self._on_legend_engine_gitlab_relation_joined)
        self.framework.observe(
            self.on[RELATION_NAME_ENGINE].relation_changed,
            self._on_legend_engine_gitlab_relation_changed)
        self.framework.observe(
            self.on[RELATION_NAME_ENGINE].relation_broken,
            self._on_legend_engine_gitlab_relation_broken)

        self.framework.observe(
            self.on[RELATION_NAME_STUDIO].relation_joined,
            self._on_legend_studio_gitlab_relation_joined)
        self.framework.observe(
            self.on[RELATION_NAME_STUDIO].relation_changed,
            self._on_legend_studio_gitlab_relation_changed)
        self.framework.observe(
            self.on[RELATION_NAME_STUDIO].relation_broken,
            self._on_legend_studio_gitlab_relation_broken)

        # Actions:
        self.framework.observe(
            self.on.get_redirect_uris_action,
            self._on_get_redirect_uris_actions)

    def _set_stored_defaults(self) -> None:
        self._stored.set_default(log_level="DEBUG")
        self._stored.set_default(gitlab_client_id="")
        self._stored.set_default(gitlab_client_secret="")

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
        if not self.model.config.get('access-token'):
            return None
        return gitlab.Gitlab(
            self._get_gitlab_base_url(),
            private_token=self.model.config['access-token'],
            ssl_verify=self.model.config['verify-ssl'])

    def _get_gitlab_openid_discovery_url(self):
        return GITLAB_OPENID_DISCOVERY_URL_FORMAT % {
            "base_url": self._get_gitlab_base_url()}

    def _create_gitlab_application(self):
        """Creates a GitLab application for the Legend installation and sets
        the client ID/secret in the charm's cold storage.
        Returns a `model.BlockedStatus` if there are any issues in the setup,
        or None if successful.
        """
        gitlab_client = self._gitlab_client
        if not gitlab_client:
            return model.BlockedStatus(
                "no gitlab client instance available for app creation")

        # NOTE(aznashwan): GitLab.com has disabled the application APIs:
        try:
            gitlab_client.applications.list()
        except gitlab.exceptions.GitlabAuthenticationError as err:
            logger.exception(
                "Exception occurred while attempting to list GitLab apps: %s",
                err)
            return model.BlockedStatus(
                "failed to authorize against gitlab, are the credentials "
                "correct?")
        except gitlab.exceptions.GitlabError as err:
            logger.exception(
                "Exception occurred while attempting to list GitLab apps: %s",
                err)
            if getattr(err, 'response_code', 0) == 403:
                return model.BlockedStatus(
                    "gitlab refused access to the applications apis with a 403"
                    ", ensure the configured gitlab host can create "
                    "application or manuallly create one")
            return model.BlockedStatus(
                "exception occurred while attempting to list existing GitLab "
                "apps")

        redirect_uris = self._get_legend_services_redirect_uris()
        if not redirect_uris:
            return model.BlockedStatus(
                "cannot create gitlab app without all legend "
                "services related")

        # TODO(aznashwan): make app trusted:
        # https://github.com/finos/legend/blob/master/installers/docker-compose/legend/scripts/setup-gitlab.sh#L36-L42
        app = self._gitlab_client.applications.create({
            "name": self.model.config['application-name'],
            "scopes": " ".join(GITLAB_REQUIRED_SCOPES),
            "redirect_uri": redirect_uris})

        self._stored.gitlab_client_id = app.application_id
        self._stored.gitlab_client_secret = app.secret

    def _check_gitlab_app_name_available(self, app_name):
        if not self._gitlab_client:
            return None
        apps = self._gitlab_client.applications.list()
        matches = [app for app in apps if app.application_name == app_name]
        return not matches

    def _check_set_up_gitlab_application(self):
        """Checks whether either GitLab App bypass ID/secret was provided, or
        attempts to create a new application on GitLab otherwise.
        Either way, the client ID/secret of the app is set within stored state.
        """
        bypass_client_id = self.model.config['bypass-client-id']
        bypass_client_secret = self.model.config['bypass-client-secret']
        if all([bypass_client_id, bypass_client_secret]):
            logger.info(
                "### Using pre-seeded Gitlab application ID/settings.")
            self._stored.gitlab_client_id = bypass_client_id
            self._stored.gitlab_client_secret = bypass_client_secret
            return None

        # Check GitLab client available:
        _ = self._gitlab_client
        if not self._gitlab_client:
            return model.BlockedStatus(
                "awaiting gitlab server configuration or relation")

        # Check application with said name already exists:
        app_name = self.model.config['application-name']
        try:
            if not self._check_gitlab_app_name_available(app_name):
                return model.BlockedStatus(
                    "application with name '%s' already exists on gitlab")
        except gitlab.exceptions.GitlabError as err:
            logger.exception(
                "Exception occurred while attempting to list GitLab apps: %s",
                err)
            if getattr(err, 'response_code', 0) == 403:
                return model.BlockedStatus(
                    "gitlab refused access to the applications apis with a 403"
                    ", ensure the configured gitlab host can create "
                    "application or manuallly create one")

        # Create the GitLab app:
        return self._create_gitlab_application()

    def _get_legend_redirect_uris_from_relation(self, relation_name):
        relation = None
        try:
            relation = self.model.get_relation(relation_name)
            if not relation:
                return None
            gitlab_consumer = legend_gitlab.LegendGitlabConsumer(
                self, relation_name)
            return gitlab_consumer.get_legend_redirect_uris(relation.id)
        except model.TooManyRelatedAppsError:
            logger.error(
                "this operator does not support multiple %s relations" % (
                    relation_name))
            return None

    def _get_legend_services_redirect_uris(self):
        """Returns a string containing the service URLs in the correct order
        (Engine, SDLC, then Studio).
        Returns an empty string if not all Legend services are related.
        """
        relation_names = [
            # NOTE(aznashwan): order of these is important:
            RELATION_NAME_ENGINE,
            RELATION_NAME_SDLC,
            RELATION_NAME_STUDIO]

        # NOTE: it is okay for a service to not have any redirect URIs
        # (i.e. empty string), but not okay for them to not be set (i.e. None):
        redirect_uris = ""
        for relation_name in relation_names:
            uris = self._get_legend_redirect_uris_from_relation(relation_name)
            if uris is None:
                logger.warning(
                    "Mussing redirect URIs for '%s' relation.", relation_name)
                return ""
            redirect_uris = "%s\n%s" % (redirect_uris, "\n".join(uris))
        redirect_uris = redirect_uris.strip("\n")

        return redirect_uris

    def _check_legend_services_relations_status(self):
        """Checks whether all the required Legend services were related.
        Returns None if all the relations are present, or a
        `model.BlockedStatus` with a relevant message otherwise.
        """
        charms_to_relation_names_map = {
            "finos-legend-sdlc-k8s": RELATION_NAME_SDLC,
            "finos-legend-engine-k8s": RELATION_NAME_ENGINE,
            "finos-legend-studio-k8s": RELATION_NAME_STUDIO
        }
        # NOTE(aznashwan): it is acceptable for a service to have no redirect
        # URIs (empty string), but not None:
        missing = [
            charm_name
            for charm_name, rel_name in charms_to_relation_names_map.items()
            if self._get_legend_redirect_uris_from_relation(rel_name) is None]
        if missing:
            return model.BlockedStatus(
                "requires relating to following legend services: %s" % (
                    ", ".join(missing)))
        return None

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

    def _set_legend_gitlab_data_in_relation(
            self, relation_name, gitlab_relation_data, validate_creds=True):
        """Sets the provided GitLab data into the given relation.
        Returns a `model.BlockedStatus` is something goes wrong, else None.
        """
        relation = None
        try:
            relation = self.model.get_relation(relation_name)
        except model.TooManyRelatedAppsError:
            return model.BlockedStatus(
                "this operator does not support multiple %s relations" % (
                    relation_name))
        if not relation:
            logger.info("No '%s' relation present", relation_name)
            return None

        try:
            legend_gitlab.set_legend_gitlab_creds_in_relation_data(
                relation.data[self.app], gitlab_relation_data,
                validate_creds=validate_creds)
        except ValueError as ex:
            logger.warning(
                "Error occurred while setting GitLab creds relation "
                "data: %s", str(ex))
            return model.BlockedStatus(
                "failed to set gitlab credentials in %s relation" % (
                    relation_name))
        return None

    def _set_gitlab_data_in_all_relations(
            self, gitlab_relation_data, validate_creds=True):
        """Sets the provided GitLab data into all the relations with the
        Legend services.
        Returns a `model.BlockedStatus` is something goes wrong, else None.
        """
        for relation_name in ALL_LEGEND_RELATION_NAMES:
            blocked = self._set_legend_gitlab_data_in_relation(
                relation_name, gitlab_relation_data,
                validate_creds=validate_creds)
            if blocked:
                return blocked

    def _update_charm_status(self):
        """Updates the status of the charm as well as all relations."""
        possible_blocked_status = (
            self._check_legend_services_relations_status())
        if possible_blocked_status:
            self.unit.status = possible_blocked_status
            return

        possible_blocked_status = self._check_set_up_gitlab_application()
        if possible_blocked_status:
            self.unit.status = possible_blocked_status
            return

        gitlab_relation_data = self._get_gitlab_relation_data()
        if not gitlab_relation_data:
            self.unit.status = model.BlockedStatus(
                "awaiting gitlab server configuration or relation")
            return
        # propagate the relation data:
        possible_blocked_status = self._set_gitlab_data_in_all_relations(
            gitlab_relation_data, validate_creds=False)
        if possible_blocked_status:
            self.unit.status = possible_blocked_status
            return

        self.unit.status = model.ActiveStatus()

    def _on_install(self, event: charm.InstallEvent):
        self._update_charm_status()

    def _on_config_changed(self, _) -> None:
        self._update_charm_status()

    def _on_gitlab_relation_joined(self, event: charm.RelationJoinedEvent):
        # TODO(aznashwan): eventual GitLab operator relation:
        pass

    def _on_gitlab_relation_changed(
            self, event: charm.RelationChangedEvent) -> None:
        # TODO(aznashwan): eventual GitLab operator relation:
        pass

    def _on_legend_sdlc_gitlab_relation_joined(
            self, event: charm.RelationJoinedEvent) -> None:
        pass

    def _on_legend_sdlc_gitlab_relation_changed(
            self, event: charm.RelationChangedEvent) -> None:
        self._update_charm_status()

    def _on_legend_sdlc_gitlab_relation_broken(
            self, event: charm.RelationBrokenEvent) -> None:
        self._update_charm_status()

    def _on_legend_engine_gitlab_relation_joined(
            self, event: charm.RelationJoinedEvent) -> None:
        pass

    def _on_legend_engine_gitlab_relation_changed(
            self, event: charm.RelationChangedEvent) -> None:
        self._update_charm_status()

    def _on_legend_engine_gitlab_relation_broken(
            self, event: charm.RelationBrokenEvent) -> None:
        self._update_charm_status()

    def _on_legend_studio_gitlab_relation_joined(
            self, event: charm.RelationJoinedEvent) -> None:
        pass

    def _on_legend_studio_gitlab_relation_changed(
            self, event: charm.RelationChangedEvent) -> None:
        self._update_charm_status

    def _on_legend_studio_gitlab_relation_broken(
            self, event: charm.RelationBrokenEvent) -> None:
        self._update_charm_status()

    def _on_get_redirect_uris_actions(self, event: charm.ActionEvent):
        redirect_uris = self._get_legend_services_redirect_uris()
        if not redirect_uris:
            raise ValueError(
                "Need to have all Legend services related to return redirect "
                "URIs.")
        event.set_results({"result": redirect_uris})


if __name__ == "__main__":
    main.main(LegendGitlabIntegratorCharm)