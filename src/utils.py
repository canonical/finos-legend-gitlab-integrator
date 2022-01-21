# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module containing various utils used by the GitLab Integration Charm."""

import base64
import logging
import ssl

import requests

# inspired by: https://stackoverflow.com/questions/16903528/how-to-get-response-ssl-certificate-from-requests-in-python  # noqa
HTTPResponse = requests.packages.urllib3.response.HTTPResponse
_HTTPResponse__init__ = HTTPResponse.__init__

HTTPAdapter = requests.adapters.HTTPAdapter
_build_response = HTTPAdapter.build_response


def _new_httpresponse__init__(self, *args, **kwargs):
    _HTTPResponse__init__(self, *args, **kwargs)

    # NOTE(claudiub): The ssl library returns a PEM certificate, but we're
    # converting it to DER in the end.
    self.peer_cert = None
    try:
        self.peer_cert = self.connection.sock.getpeercert(True)
    except AttributeError:
        pass


def _new_build_response(self, request, resp):
    response = _build_response(self, request, resp)
    try:
        response.peer_cert = resp.peer_cert
    except AttributeError:
        pass
    return response


HTTPResponse.__init__ = _new_httpresponse__init__
HTTPAdapter.build_response = _new_build_response


def get_gitlab_host_cert_b64(host, port):
    """Returns the server certificate from the given host and port."""
    try:
        # NOTE(aznashwan): we can also send the .PEM but there's no point in base64-ing it twice:
        cert = ssl.get_server_certificate((host, port))
        return base64.b64encode(ssl.PEM_cert_to_DER_cert(cert)).decode()
    except Exception as ex:
        logging.warning(
            "Encountered exception while getting the '%s:%s' SSL certificate. "
            "Using alternate method. Exception: %s",
            host,
            port,
            ex,
        )

    # NOTE(claudiub): Since we're not logged in, accessing gitlab.com will
    # redirect us to about.gitlab.com, which means that we won't actually get
    # gitlab.com's SSL certificate. For this, we're using gitlab.com/explore
    # instead, which has no redirects.
    # TODO(claudiub): Find a cleaner approach.
    url = "https://%s:%s/explore" % (host, port)
    response = requests.get(url)
    if not response.peer_cert:
        msg = "Could not fetch the SSL certificate from %s:%s" % (host, port)
        raise Exception(msg)
    return base64.b64encode(response.peer_cert).decode()
