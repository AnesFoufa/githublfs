from unittest.mock import patch, MagicMock

from github import UnknownObjectException
from requests_mock import Mocker as RequestMocker

from githublfs import commit_lfs_file
from tests.doubles import FakeGithubContent
from pytest import fixture


@patch("githublfs.Github")
def test_commit_lfs_file_should_upload_and_verify_file_and_update_pointer_when_file_not_uploaded_and_exists_in_repo(
    github_class,
    branch,
    path,
    content,
    content_hash,
    message,
    repository,
    token,
    actions_with_upload_verify,
    pointer_content,
):
    fake_repository = MagicMock()
    github_content = FakeGithubContent(path="fake_path", sha="fake_sha")
    fake_repository.get_contents.return_value = github_content
    _set_up_fake_github(fake_repository, github_class)
    lfs_server_url = f"https://github.com/{repository}.git/info/lfs/objects/batch"
    response_body = {"objects": [{"actions": actions_with_upload_verify}]}
    upload_url = actions_with_upload_verify["upload"]["href"]
    upload_headers = actions_with_upload_verify["upload"]["header"]
    verify_url = actions_with_upload_verify["verify"]["href"]
    verify_headers = actions_with_upload_verify["verify"]["header"]

    _set_up_requests_mocker_and_call_commit_lfs_file(
        branch,
        content,
        lfs_server_url,
        message,
        path,
        repository,
        response_body,
        token,
        upload_url,
        upload_headers,
        verify_url,
        verify_headers,
    )
    fake_repository.update_file.assert_called_once_with(
        path=github_content.path,
        sha=github_content.sha,
        content=pointer_content,
        message=message,
        branch=branch,
    )


@patch("githublfs.Github")
def test_commit_lfs_file_should_upload_and_verify_file_and_create_pointer_when_file_not_uploaded_and_not_exists_in_repo(
    github_class,
    branch,
    path,
    content,
    content_hash,
    message,
    repository,
    token,
    actions_with_upload_verify,
    pointer_content,
):
    fake_repository = MagicMock()
    fake_repository.get_contents.side_effect = UnknownObjectException(
        status="status", data="data", headers=None
    )
    _set_up_fake_github(fake_repository, github_class)
    lfs_server_url = f"https://github.com/{repository}.git/info/lfs/objects/batch"

    upload_url = actions_with_upload_verify["upload"]["href"]
    upload_headers = actions_with_upload_verify["upload"]["header"]
    verify_url = actions_with_upload_verify["verify"]["href"]
    verify_headers = actions_with_upload_verify["verify"]["header"]
    response_body = {"objects": [{"actions": actions_with_upload_verify}]}

    _set_up_requests_mocker_and_call_commit_lfs_file(
        branch,
        content,
        lfs_server_url,
        message,
        path,
        repository,
        response_body,
        token,
        upload_url,
        upload_headers,
        verify_url,
        verify_headers,
    )

    fake_repository.create_file.assert_called_once_with(
        path=path,
        branch=branch,
        content=pointer_content,
        message=message,
    )


@patch("githublfs.Github")
def test_commit_lfs_file_should_upload_and_not_verify_file_and_create_pointer_when_no_verify_data_returned(
    github_class,
    branch,
    path,
    content,
    content_hash,
    pointer_content,
    message,
    repository,
    token,
    upload_url,
    upload_headers,
):
    fake_repository = MagicMock()
    github_content = FakeGithubContent(path="fake_path", sha="fake_sha")
    fake_repository.get_contents.return_value = github_content
    _set_up_fake_github(fake_repository, github_class)
    lfs_server_url = f"https://github.com/{repository}.git/info/lfs/objects/batch"
    first_object_actions = {
        "upload": {
            "href": upload_url,
            "header": upload_headers,
        },
    }
    response_body = {"objects": [{"actions": first_object_actions}]}
    with RequestMocker() as m:
        m.post(url=lfs_server_url, status_code=200, json=response_body)
        m.put(url=upload_url, status_code=200, headers=upload_headers)
        commit_lfs_file(
            path=path,
            content=content,
            branch=branch,
            message=message,
            repo=repository,
            token=token,
        )

    fake_repository.update_file.assert_called_once_with(
        path=github_content.path,
        sha=github_content.sha,
        content=pointer_content,
        message=message,
        branch=branch,
    )


@patch("githublfs.Github")
def test_commit_lfs_file_should_not_upload_when_no_upload_file_url(
    github_class,
    branch,
    path,
    content,
    content_hash,
    pointer_content,
    message,
    repository,
    token,
    verify_headers,
    verify_url,
):
    fake_repository = MagicMock()
    github_content = FakeGithubContent(path="fake_path", sha="fake_sha")
    fake_repository.get_contents.return_value = github_content
    _set_up_fake_github(fake_repository, github_class)
    lfs_server_url = f"https://github.com/{repository}.git/info/lfs/objects/batch"

    first_object_actions = {
        "verify": {
            "href": verify_url,
            "header": verify_headers,
        },
    }
    response_body = {"objects": [{"actions": first_object_actions}]}
    with RequestMocker() as m:
        m.post(url=lfs_server_url, status_code=200, json=response_body)
        commit_lfs_file(
            path=path,
            content=content,
            branch=branch,
            message=message,
            repo=repository,
            token=token,
        )

    fake_repository.update_file.assert_called_once_with(
        path=github_content.path,
        sha=github_content.sha,
        content=pointer_content,
        message=message,
        branch=branch,
    )


@patch("githublfs.Github")
def test_commit_lfs_file_should_update_many_files_when_many_corresponding_files_found_in_repo(
    github_class,
    branch,
    path,
    content,
    content_hash,
    message,
    repository,
    token,
    verify_headers,
    verify_url,
    pointer_content,
):
    fake_repository = MagicMock()
    github_contents = [
        FakeGithubContent(path="fake_path_1", sha="fake_sha_1"),
        FakeGithubContent(path="fake_path_2", sha="fake_sha_2"),
    ]
    fake_repository.get_contents.return_value = github_contents
    _set_up_fake_github(fake_repository, github_class)
    lfs_server_url = f"https://github.com/{repository}.git/info/lfs/objects/batch"
    first_object_actions = {}
    response_body = {"objects": [{"actions": first_object_actions}]}
    with RequestMocker() as m:
        m.post(url=lfs_server_url, status_code=200, json=response_body)
        commit_lfs_file(
            path=path,
            content=content,
            branch=branch,
            message=message,
            repo=repository,
            token=token,
        )
    fake_repository.update_file.assert_any_call(
        path=github_contents[1].path,
        sha=github_contents[1].sha,
        content=pointer_content,
        message=message,
        branch=branch,
    )
    fake_repository.update_file.assert_any_call(
        path=github_contents[0].path,
        sha=github_contents[0].sha,
        content=pointer_content,
        message=message,
        branch=branch,
    )


def _set_up_fake_github(fake_repository, github_class):
    fake_github = MagicMock()
    fake_github.get_repo.return_value = fake_repository
    github_class.return_value = fake_github


def _set_up_requests_mocker_and_call_commit_lfs_file(
    branch,
    content,
    lfs_server_url,
    message,
    path,
    repository,
    response_body,
    token,
    upload_url,
    upload_headers,
    verify_url,
    verify_headers,
):
    with RequestMocker() as m:
        m.post(url=lfs_server_url, status_code=200, json=response_body)
        m.put(url=upload_url, status_code=200, headers=upload_headers)
        m.post(url=verify_url, status_code=200, headers=verify_headers)
        commit_lfs_file(
            path=path,
            content=content,
            branch=branch,
            message=message,
            repo=repository,
            token=token,
        )


@fixture()
def actions_with_upload_verify(upload_url, upload_headers, verify_url, verify_headers):
    return {
        "upload": {
            "href": upload_url,
            "header": upload_headers,
        },
        "verify": {
            "href": verify_url,
            "header": verify_headers,
        },
    }


@fixture()
def pointer_content(content_hash, content):
    return f"version https://git-lfs.github.com/spec/v1\noid sha256:{content_hash}\nsize {len(content)}\n"
