# Some repositories (such as Devpi) expose the Pypi legacy API
# (https://warehouse.pypa.io/api-reference/legacy.html).
#
# Note it is not possible to use pip
# https://discuss.python.org/t/pip-download-just-the-source-packages-no-building-no-metadata-etc/4651/12

import os
import sys
import netrc
from urllib.parse import urlparse, urlunparse
from html.parser import HTMLParser
import urllib.request
import shutil
import ssl
from os.path import normpath
from typing import Optional


# Parse the legacy index page to extract the href and package names
class Pep503(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sources = {}
        self.url = None
        self.name = None

    def handle_data(self, data):
        if self.url is not None:
            self.name = data

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for name, value in attrs:
                if name == "href":
                    self.url = value

    def handle_endtag(self, tag):
        if self.url is not None:
            self.sources[self.name] = self.url
        self.url = None

url = sys.argv[1]
reference = sys.argv[2]
package_name = sys.argv[3]
index_url = url + "/" + package_name + "/"
package_filename = sys.argv[4]

username: Optional[str] = None
password: Optional[str] = None

print(f"Looking for Poetry HTTP basic auth environment variables for reference {reference}")
username_env_var = f"POETRY_HTTP_BASIC_{reference.upper()}_USERNAME"
password_env_var = f"POETRY_HTTP_BASIC_{reference.upper()}_PASSWORD"
if username_env_var in os.environ and password_env_var in os.environ:
    print(f"Found Poetry HTTP basic auth environment variables for source `{reference}`")
    username = os.environ[username_env_var]
    password = os.environ[password_env_var]
elif "NETRC" in os.environ:
    # Parse username and password for this host from the netrc file if given.
    host = urlparse(index_url).netloc
    print(f"Looking for NETRC entry for host `{host}`")
    netrc_obj = netrc.netrc(os.environ["NETRC"])
    host = urlparse(index_url).netloc
    # Strip port number if present
    if ":" in host:
        host = host.split(":")[0]
    username, _, password = netrc_obj.authenticators(host)

print("Reading index %s" % index_url)

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

# Extract out username/password from index_url, if present.
parsed_url = urlparse(index_url)
username = parsed_url.username or username
password = parsed_url.password or password
index_url = parsed_url._replace(netloc=parsed_url.netloc.rpartition("@")[-1]).geturl()

req = urllib.request.Request(index_url)
if username and password:
    import base64

    password_b64 = base64.b64encode(":".join((username, password)).encode()).decode(
        "utf-8"
    )
    req.add_header("Authorization", "Basic {}".format(password_b64))
else:
    print("No HTTP basic auth username and password found")

response = urllib.request.urlopen(req, context=context)
index = response.read()

parser = Pep503()
parser.feed(str(index, "utf-8"))
if package_filename not in parser.sources:
    print(
        "The file %s has not be found in the index %s" % (package_filename, index_url)
    )
    exit(1)

package_file = open(package_filename, "wb")
# Sometimes the href is a relative or absolute path within the index's domain.
indicated_url = urlparse(parser.sources[package_filename])
if indicated_url.netloc == "":
    parsed_url = urlparse(index_url)

    if indicated_url.path.startswith("/"):
        # An absolute path within the index's domain.
        path = parser.sources[package_filename]
    else:
        # A relative path.
        path = parsed_url.path + "/" + parser.sources[package_filename]

    package_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            path,
            None,
            None,
            None,
        )
    )
else:
    package_url = parser.sources[package_filename]

# Handle urls containing "../"
parsed_url = urlparse(package_url)
real_package_url = urlunparse(
    (
        parsed_url.scheme,
        parsed_url.netloc,
        normpath(parsed_url.path),
        parsed_url.params,
        parsed_url.query,
        parsed_url.fragment,
    )
)
print("Downloading %s" % real_package_url)

req = urllib.request.Request(real_package_url)
if username and password:
    req.add_unredirected_header("Authorization", "Basic {}".format(password_b64))
response = urllib.request.urlopen(req, context=context)

with response as r:
    shutil.copyfileobj(r, package_file)
