from githublfs import (
    UploadAndCommitLFS,
    FileData,
    GHRepo,
    CheckUploadAndVerify,
    UploadAndVerifyData,
    URLHeaders,
    CheckFileInLFSServer,
    _parse_upload_and_verify_from_response,
    _get_github_content,
    CommitLFSPointer,
    _post_pre_upload_request_to_lfs_server,
    _upload_file_to_lfs_server,
    _verify_file_uploaded,
    CommitFile,
)
from pytest import raises

from github import UnknownObjectException
from requests_mock import Mocker as RequestMocker
from unittest.mock import patch, MagicMock

from tests.doubles import FakeGithubContent


class Spy:
    def __init__(self, value_to_return=None):
        self.called_with = None
        self.never_called = True
        self.value_to_return = value_to_return

    def __call__(self, **kwargs):
        self.never_called = False
        self.called_with = kwargs
        return self.value_to_return

    def assert_called_with(self, **kwargs):
        self.assert_called()
        assert kwargs == self.called_with

    def assert_never_called(self):
        assert (
            self.never_called
        ), f"Spy object not expected to be called but was called with {self.called_with}"

    def assert_called(self):
        assert not self.never_called, f"Spy object expected to be called but was not"


def test_upload_and_commit(
    branch, token, path, repository, content, message, content_hash
):
    fake_upload_lfs = Spy()
    fake_commit_pointer = Spy()
    upload_and_commit_lfs = UploadAndCommitLFS(
        upload_lfs=fake_upload_lfs, commit_pointer=fake_commit_pointer
    )
    upload_and_commit_lfs(
        repository=repository,
        content=content,
        message=message,
        token=token,
        path=path,
        branch=branch,
    )

    gh_repo = GHRepo(name=repository, token=token)
    file_data = FileData(digest=content_hash, content=content)

    fake_upload_lfs.assert_called_with(
        file_data=file_data,
        gh_repo=gh_repo,
    )
    fake_commit_pointer.assert_called_with(
        gh_repo=gh_repo, branch=branch, message=message, path=path, file_data=file_data
    )


def test_check_upload_and_verify_should_neither_upload_nor_verify_if_file_already_uploaded(
    gh_repo, file_data
):
    fake_check_uploaded = Spy()
    fake_upload = Spy()
    fake_verify = Spy()

    check_upload_and_verify = CheckUploadAndVerify(
        check_uploaded=fake_check_uploaded, upload=fake_upload, verify=fake_verify
    )
    check_upload_and_verify(gh_repo=gh_repo, file_data=file_data)
    fake_check_uploaded.assert_called_with(gh_repo=gh_repo, file_data=file_data)
    fake_upload.assert_never_called()
    fake_verify.assert_never_called()


def test_check_upload_and_verify_should_upload_and_not_verify_when_file_not_uploaded_and_no_verification_data_returned_from_check(
    gh_repo, file_data, upload_url_headers
):
    upload_verify_data = UploadAndVerifyData(upload=upload_url_headers)
    fake_check_uploaded, fake_upload, fake_verify = _set_up_test_doubles(
        upload_verify_data
    )

    check_upload_and_verify = CheckUploadAndVerify(
        check_uploaded=fake_check_uploaded, upload=fake_upload, verify=fake_verify
    )
    check_upload_and_verify(gh_repo=gh_repo, file_data=file_data)
    _assert_check_and_upload_called(
        fake_check_uploaded, fake_upload, file_data, gh_repo, upload_url_headers
    )
    fake_verify.assert_never_called()


def test_check_upload_and_verify_should_upload_and_verify_when_file_not_uploaded_and_verification_data_returned_from_check(
    gh_repo, file_data, upload_url_headers, verify_url_headers
):
    upload_verify_data = UploadAndVerifyData(
        upload=upload_url_headers, verify=verify_url_headers
    )
    fake_check_uploaded, fake_upload, fake_verify = _set_up_test_doubles(
        upload_verify_data
    )

    check_upload_and_verify = CheckUploadAndVerify(
        check_uploaded=fake_check_uploaded, upload=fake_upload, verify=fake_verify
    )
    check_upload_and_verify(gh_repo=gh_repo, file_data=file_data)
    _assert_check_and_upload_called(
        fake_check_uploaded, fake_upload, file_data, gh_repo, upload_url_headers
    )
    fake_verify.assert_called_with(url_headers=verify_url_headers, file_data=file_data)


def test_check_file_in_lfs_server_should_return_none_when_parse_response_returns_none(
    gh_repo, file_data
):
    response = {"foo": "baz"}
    fake_request_file_in_server = Spy(value_to_return=response)
    fake_parse_response = Spy()
    check_file_in_lfs_server = CheckFileInLFSServer(
        request_file_in_server=fake_request_file_in_server,
        parse_response=fake_parse_response,
    )
    assert check_file_in_lfs_server(gh_repo=gh_repo, file_data=file_data) is None
    fake_request_file_in_server.assert_called_with(gh_repo=gh_repo, file_data=file_data)
    fake_parse_response.assert_called_with(response=response)


def test_check_file_in_lfs_server_should_return_upload_and_verify_data_when_parse_response_returns_them(
    gh_repo, file_data, upload_url_headers, verify_url_headers
):
    upload_verify_data = UploadAndVerifyData(
        upload=upload_url_headers, verify=verify_url_headers
    )

    response = {"foo": "baz"}
    fake_request_file_in_server = Spy(value_to_return=response)
    fake_parse_response = Spy(value_to_return=upload_verify_data)
    check_file_in_lfs_server = CheckFileInLFSServer(
        request_file_in_server=fake_request_file_in_server,
        parse_response=fake_parse_response,
    )
    assert (
        check_file_in_lfs_server(gh_repo=gh_repo, file_data=file_data)
        == upload_verify_data
    )
    fake_request_file_in_server.assert_called_with(gh_repo=gh_repo, file_data=file_data)
    fake_parse_response.assert_called_with(response=response)


def test_parse_upload_check_response_should_return_none_if_no_actions_in_first_object():
    first_object = {"foo": "bar"}
    response = {"objects": [first_object]}
    assert _parse_upload_and_verify_from_response(response) is None


def test_parse_upload_check_response_should_return_none_if_first_action_has_no_upload():
    first_object_actions = {"foo": "bar"}
    first_object = {"actions": first_object_actions}
    response = {"objects": [first_object]}
    assert _parse_upload_and_verify_from_response(response) is None


def test_parse_upload_check_response_should_return_upload_data_if_in_first_actions(
    upload_url, upload_headers
):
    first_object_actions = {
        "upload": {
            "href": upload_url,
            "header": upload_headers,
        }
    }
    first_object = {"actions": first_object_actions}
    response = {
        "objects": [
            first_object,
        ]
    }
    result = _parse_upload_and_verify_from_response(response)
    assert result.upload == URLHeaders(url=upload_url, headers=upload_headers)


def test_parse_upload_check_response_should_return_upload_and_verify_data_if_in_first_actions(
    upload_url, upload_headers, verify_url, verify_headers
):
    first_object_actions = {
        "upload": {
            "href": upload_url,
            "header": upload_headers,
        },
        "verify": {
            "href": verify_url,
            "header": verify_headers,
        },
    }
    first_object = {"actions": first_object_actions}
    response = {
        "objects": [
            first_object,
        ]
    }
    result = _parse_upload_and_verify_from_response(response)
    assert result.upload == URLHeaders(url=upload_url, headers=upload_headers)
    assert result.verify == URLHeaders(url=verify_url, headers=verify_headers)


class FakeRepository:
    def __init__(self, value_to_return=None, exception_to_raise=None):
        self.path = None
        self.ref = None
        self._value_to_return = value_to_return
        self._exception_to_raise = exception_to_raise
        self._create_file_kwargs = None

    def get_contents(self, path, ref):
        self.path = path
        self.ref = ref
        if self._exception_to_raise:
            raise self._exception_to_raise
        return self._value_to_return

    def assert_get_contents_called_with_path(self, path):
        assert self.path == path

    def assert_get_contents_called_with_ref(self, ref):
        assert self.ref == ref


def test_get_github_file_content_should_return_empty_list_when_repository_returns_empty_list(
    path, branch
):
    fake_repository = FakeRepository(value_to_return=[])

    assert (
        _get_github_content(repository=fake_repository, path=path, branch=branch) == []
    )
    fake_repository.assert_get_contents_called_with_path(path)
    fake_repository.assert_get_contents_called_with_ref(branch)


def test_get_github_file_content_should_return_none_when_repository_raises_unknown_object(
    path, branch
):
    fake_repository = FakeRepository(
        exception_to_raise=UnknownObjectException(data=None, headers=None, status=404)
    )

    assert (
        _get_github_content(repository=fake_repository, path=path, branch=branch)
        is None
    )
    fake_repository.assert_get_contents_called_with_path(path)
    fake_repository.assert_get_contents_called_with_ref(branch)


def test_get_github_file_content_should_return_file_contents_content_when_repository_returns_non_empty_list_of_contents(
    path, branch
):
    contents = ["foo", "bar"]
    fake_repository = FakeRepository(value_to_return=contents)

    assert (
        _get_github_content(repository=fake_repository, path=path, branch=branch)
        == contents
    )
    fake_repository.assert_get_contents_called_with_path(path)
    fake_repository.assert_get_contents_called_with_ref(branch)


def test_get_github_file_content_should_return_first_content_in_list_when_repository_returns_content(
    content, path, branch
):
    fake_repository = FakeRepository(value_to_return=content)

    assert _get_github_content(
        repository=fake_repository, path=path, branch=branch
    ) == [content]
    fake_repository.assert_get_contents_called_with_path(path)
    fake_repository.assert_get_contents_called_with_ref(branch)


def test_commit_lfs_pointer_should_call_commit_file(
    file_data, gh_repo, branch, path, message
):
    fake_commit_file = Spy()
    commit_lfs_pointer = CommitLFSPointer(commit_file=fake_commit_file)

    commit_lfs_pointer(
        file_data=file_data, gh_repo=gh_repo, branch=branch, message=message, path=path
    )

    content = f"version https://git-lfs.github.com/spec/v1\noid sha256:{file_data.digest}\nsize {file_data.size}\n"
    fake_commit_file.assert_called_with(
        gh_repo=gh_repo, branch=branch, message=message, path=path, content=content
    )


def test_post_pre_upload_request_to_lfs_server_should_request_with_correct_url_and_payload_and_return_json_body(
    gh_repo, file_data
):
    url_to_query = f"https://github.com/{gh_repo.name}.git/info/lfs/objects/batch"
    request_body = {
        "operation": "upload",
        "transfers": ["basic"],
        "objects": [
            {
                "oid": file_data.digest,
                "size": file_data.size,
            }
        ],
    }
    response_body = {"foo": "bar"}
    with RequestMocker() as m:
        m.post(url=url_to_query, status_code=200, json=response_body)
        res = _post_pre_upload_request_to_lfs_server(
            file_data=file_data, gh_repo=gh_repo
        )

    assert res == response_body
    assert m.called_once
    last_request = m.last_request
    assert last_request.url == url_to_query
    request_headers = last_request.headers
    assert request_headers["Accept"] == "application/vnd.git-lfs+json"
    assert request_headers["Content-Type"] == "application/json"
    assert last_request.json() == request_body


def test_post_pre_upload_request_to_lfs_server_should_raise_assertion_error_when_status_code_is_an_error(
    gh_repo, file_data
):
    url_to_query = f"https://github.com/{gh_repo.name}.git/info/lfs/objects/batch"
    with RequestMocker() as m:
        m.post(url=url_to_query, status_code=400)
        with raises(AssertionError):
            _post_pre_upload_request_to_lfs_server(file_data=file_data, gh_repo=gh_repo)


def test_upload_file_to_lfs_server_should_have_correct_request(
    upload_url_headers, content
):
    with RequestMocker() as m:
        m.put(url=upload_url_headers.url, status_code=200)
        _upload_file_to_lfs_server(url_headers=upload_url_headers, content=content)

    assert m.called_once
    last_request = m.last_request
    request_headers = last_request.headers
    for (key, value) in upload_url_headers.headers.items():
        assert request_headers[key] == value
    assert request_headers["Content-Type"] == "application/octet-stream"
    assert last_request.body == content


class FakeGithub:
    def __init__(self, repository):
        self._repository = repository
        self._called_with = None

    def get_repo(self, full_name_or_id, *args, **kwargs):
        self._called_with = full_name_or_id
        return self._repository

    def assert_called_with(self, full_name_or_id):
        assert full_name_or_id == self._called_with


def test_verify_file_uploaded_should_request_with_correct_headers_and_body(
    verify_url_headers, file_data
):
    with RequestMocker() as m:
        m.post(verify_url_headers.url, status_code=200)
        _verify_file_uploaded(url_headers=verify_url_headers, file_data=file_data)
    assert m.called_once
    last_request = m.last_request
    request_headers = last_request.headers
    for (key, value) in verify_url_headers.headers.items():
        assert request_headers[key] == value
    assert request_headers["Content-Type"] == "application/vnd.git-lfs+json"
    expected_request_body = f"oid={file_data.digest}&size={file_data.size}"
    assert last_request.body == expected_request_body


@patch("githublfs.Github")
def test_commit_file_should_create_file_if_not_exists(
    fake_github_class, gh_repo, branch, content, message, path
):
    fake_repository = MagicMock()
    fake_github = FakeGithub(fake_repository)
    fake_github_class.return_value = fake_github
    fake_get_content = Spy()

    commit_file = CommitFile(get_file_content=fake_get_content)

    commit_file(
        gh_repo=gh_repo, branch=branch, content=content, message=message, path=path
    )

    fake_github_class.assert_called_with(gh_repo.token)
    fake_github.assert_called_with(gh_repo.name)
    fake_repository.create_file.assert_called_once_with(
        branch=branch, content=content, message=message, path=path
    )


@patch("githublfs.Github")
def test_commit_file_should_update_files_if_exist(
    fake_github_class, gh_repo, branch, content, message, path
):
    fake_repository = MagicMock()
    fake_github = FakeGithub(fake_repository)
    fake_github_class.return_value = fake_github
    gh_contents = [
        FakeGithubContent(path="github_content_path_1", sha="github_content_sha_1"),
        FakeGithubContent(path="github_content_path_2", sha="github_content_sha_2"),
    ]
    fake_get_content = Spy(value_to_return=gh_contents)

    commit_file = CommitFile(get_file_content=fake_get_content)

    commit_file(
        gh_repo=gh_repo, branch=branch, content=content, message=message, path=path
    )

    fake_github_class.assert_called_with(gh_repo.token)
    fake_github.assert_called_with(gh_repo.name)
    for gh_content in gh_contents:
        fake_repository.update_file.assert_any_call(
            sha=gh_content.sha,
            content=content,
            message=message,
            path=gh_content.path,
            branch=branch,
        )


def _assert_check_and_upload_called(
    fake_check_uploaded,
    fake_upload,
    file_data,
    gh_repo,
    upload_url_headers,
):
    fake_check_uploaded.assert_called_with(gh_repo=gh_repo, file_data=file_data)
    fake_upload.assert_called_with(
        url_headers=upload_url_headers, content=file_data.content
    )


def _set_up_test_doubles(upload_verify_data):
    fake_check_uploaded = Spy(value_to_return=upload_verify_data)
    fake_upload = Spy()
    fake_verify = Spy()
    return fake_check_uploaded, fake_upload, fake_verify
