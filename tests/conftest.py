from _pytest.fixtures import fixture

from githublfs import GHRepo, FileData, URLHeaders


@fixture()
def branch():
    return "main"


@fixture()
def token():
    return "fake_token"


@fixture()
def path():
    return "assets/logo.jpg"


@fixture()
def repository():
    return "AnesFoufa/githublfs"


@fixture()
def content():
    return b"fake content"


@fixture()
def message():
    return "commit message"


@fixture()
def content_hash():
    return "98b1ae45059b004178a8eee0c1f6179dcea139c0fd8a69ee47a6f02d97af1f17"


@fixture()
def gh_repo(repository, token):
    return GHRepo(name=repository, token=token)


@fixture()
def file_data(content_hash, content):
    return FileData(digest=content_hash, content=content)


@fixture()
def upload_url():
    return "http://upload_url/"


@fixture()
def upload_headers():
    return {"foo": "bar"}


@fixture()
def upload_url_headers(upload_url, upload_headers):
    return URLHeaders(url=upload_url, headers=upload_headers)


@fixture()
def verify_url():
    return "http://verify_url/"


@fixture()
def verify_headers():
    return {"spam": "baz"}


@fixture()
def verify_url_headers(verify_url, verify_headers):
    return URLHeaders(url=verify_url, headers=verify_headers)
