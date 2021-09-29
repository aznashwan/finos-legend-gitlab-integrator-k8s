# FINOS Legend GitLab Integrator

## Description

The Legend Operators package the core [FINOS Legend](https://legend.finos.org)
components for quick and easy deployment of a Legend stack.

This repository contains a [Juju](https://juju.is/) Charm for
deploying a service which exposes a pre-existing GitLab endpoint
for the other Legend components.

The full Legend solution can be installed with the dedicated
[Legend bundle](https://charmhub.io/finos-legend-bundle).


## Usage

The Legend Gitlab Integrator can be deployed by running:

```sh
$ juju deploy finos-legend-gitlab-integrator-k8s --channel=edge
```


## Relations

The standalone Integrator will initially be blocked, and will require being
related to the Legend components for it be ready to be configured with GitLab
Creds:

```sh
# Relate to the legend services:
$ juju relate finos-legend-gitlab-integrator-k8s finos-legend-sdlc-k8s
$ juju relate finos-legend-gitlab-integrator-k8s finos-legend-engine-k8s
$ juju relate finos-legend-gitlab-integrator-k8s finos-legend-studio-k8s
```

## GitLab Configuration:
### A: Using private GitLab (recommended)

Prerequisites:
* a private GitLab deployment configured to use HTTPS
* a [personal access token](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html) for the GitLab
* the certificate (`*.der`) for the GitLab deployment

```bash
# Convert the '*.der' into base64
CERT=`base64 -w 0 /path/to/certfile.der`

juju config finos-legend-gitlab-integrator-k8s \
    gitlab-host=10.107.2.9 gitlab-host-der-b64="$CERT" gitlab-port=443 \
    access-token="CqVrcbHOMeU="
```

### B: Using pre-created GitLab application

Prerequisites:
* access to the portal of [gitlab.com](https://gitlab.com) or the private GitLab
* application creation rights on said account

#### Creating the GitLab Application:
* login to Gitlab
* Go top-left to User Settings > Applications
* Create a new application with the following:
  - Name: "Legend Demo"
  - Confidential: yes
  - Scopes: openid, profile, api
  - Redirect URI: set it to http://localhost:8080/callback
* __Save the Client ID and Secret for later__

#### Setting the GitLab application creds:

```bash
# NOTE: one may optionally add the following, else it defaults to gitlab.com:
# api-scheme=http gitlab-host=10.107.2.9 gitlab-port 443
juju config finos-legend-gitlab-integrator-k8s \
    bypass-client-id=<cliend id> \
    bypass-client-secret=<client secret>
```

#### Fetching the redirect URIs:

Once the `finos-legend-gitlab-integrator-k8s` becomes `active`:
```bash
user@ubuntu:~$ juju status | grep gitlab
finos-legend-gitlab-integrator-k8s/0*  active    idle   10.1.184.238

user@ubuntu:~$ juju run-action finos-legend-gitlab-integrator-k8s/0 get-redirect-uris
Action queued with id: "2"

user@ubuntu:~$ juju show-action-output 2
UnitId: finos-legend-gitlab-integrator-k8s/0
id: "2"
results:
  result: |-
    http://10.1.184.224:6060/api/callback
    http://10.1.184.236:7070/api/auth/callback
    http://10.1.184.236:7070/api/pac4j/login/callback
    http://10.1.184.241:8080/studio/log.in/callback
status: completed
timing:
  completed: 2021-09-27 18:50:39 +0000 UTC
  enqueued: 2021-09-27 18:50:38 +0000 UTC
  started: 2021-09-27 18:50:38 +0000 UTC
```

#### Setting the above redirect URIs into GitLab:
* log back into your GitLab portal
* go to the application created previously
* edit the Redirect URI setting of the application
* paste the output of the `result` field from the `juju show-action-output`
  command run previously

## OCI Images

This charm has no actual workload container, but deploys a shell container
based on the [Ubuntu Xenial](https://hub.docker.com/_/ubuntu) image.
