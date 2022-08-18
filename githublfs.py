from dataclasses import dataclass
from hashlib import sha256
from typing import Optional

import requests
from github import Github, UnknownObjectException
from github.Repository import Repository
from github.ContentFile import ContentFile

__all__ = ["commit_lfs_file"]


@dataclass(frozen=True)
class URLHeaders:
    url: str
    headers: dict


@dataclass
class UploadAndVerify:
    upload: URLHeaders
    verify: Optional[URLHeaders] = None


@dataclass(frozen=True)
class FileData:
    digest: str
    content: bytes

    @property
    def size(self):
        return len(self.content)


@dataclass(frozen=True)
class GHRepo:
    name: str
    token: str


def commit_lfs_file(
    repo: str, token: str, path: str, content: bytes, branch: str, message: str
):
    """
    Commits a file to a Github repository using LFS.
    :param repo: Complete name of the Github repository. Example "AnesFoufa/githublfs"
    :param token: Github Personal access token with "repo" scope
    :param path: path to the file to commit. Example "assets/logo.jpg"
    :param content: Binary content of the file to update.
    :param branch: Name of the branch to commit to. Example "main".
    :param message: Commit message. Example "update logo"
    :return: None
    """

    # Build needed data
    digest = _hash_content(content)
    file_data = FileData(digest=digest, content=content)
    gh_repo = GHRepo(name=repo, token=token)

    # Upload data if not in server and commit pointer
    upload_and_verification_urls_and_headers = _check_file_in_lfs_server(
        gh_repo=gh_repo,
        file_data=file_data,
    )
    # If the file is not already in the server
    if upload_and_verification_urls_and_headers:
        _upload_and_verify(
            file_data=file_data,
            urls_and_headers=upload_and_verification_urls_and_headers,
        )
    _commit_lfs_pointer(
        branch=branch, file_data=file_data, message=message, path=path, gh_repo=gh_repo
    )


def _hash_content(content: bytes) -> str:
    hasher = sha256()
    hasher.update(content)
    return hasher.hexdigest()


def _check_file_in_lfs_server(
    gh_repo: GHRepo, file_data: FileData
) -> Optional[UploadAndVerify]:
    """
    :param gh_repo: Github repo data.
    :param file_data: File to check data.
    :return: None if file already uploaded, UploadAndVerify headers ans urls otherwise.
    """
    json_response = _post_pre_upload_request_to_lfs_server(
        file_data=file_data, gh_repo=gh_repo
    )
    res = _parse_upload_and_verify_from_response(json_response)
    return res


def _upload_and_verify(file_data: FileData, urls_and_headers: UploadAndVerify):
    """
    Upload file to LFS and optionally verify it is correctly uploaded.
    :param file_data: File to verify.
    :param urls_and_headers: Url and headers for upload and verification.
    :return: None
    :raise AssertionError if LFS server does not behave as expected.
    """
    _upload_file_to_lfs_server(
        url_headers=urls_and_headers.upload, content=file_data.content
    )
    if urls_and_headers.verify:
        _verify_file_uploaded(url_headers=urls_and_headers.verify, file_data=file_data)


def _commit_lfs_pointer(
    branch: str, file_data: FileData, message: str, path: str, gh_repo: GHRepo
):
    pointer_content = f"version https://git-lfs.github.com/spec/v1\noid sha256:{file_data.digest}\nsize {file_data.size}\n"
    _commit_file(
        gh_repo=gh_repo,
        path=path,
        content=pointer_content,
        branch=branch,
        message=message,
    )


def _post_pre_upload_request_to_lfs_server(file_data: FileData, gh_repo: GHRepo):
    url = f"https://github.com/{gh_repo.name}.git/info/lfs/objects/batch"
    headers = {
        "Content-type": "application/json",
        "Accept": "application/vnd.git-lfs+json",
    }
    payload = {
        "operation": "upload",
        "transfers": ["basic"],
        "objects": [
            {
                "oid": file_data.digest,
                "size": file_data.size,
            }
        ],
    }
    response = requests.post(
        url=url, headers=headers, json=payload, auth=(gh_repo.token, "")
    )
    assert 200 <= response.status_code < 300, _error_message(response)
    json_response = response.json()
    return json_response


def _parse_upload_and_verify_from_response(json_response) -> Optional[UploadAndVerify]:
    first_object = json_response["objects"][0]
    res = None
    if "actions" in first_object and "upload" in first_object["actions"]:
        actions_dict = first_object["actions"]
        upload_dict = actions_dict["upload"]
        upload_url_and_headers = URLHeaders(
            headers=upload_dict["header"], url=upload_dict["href"]
        )
        res = UploadAndVerify(upload=upload_url_and_headers)
        if "verify" in actions_dict:
            verify_dict = actions_dict["verify"]
            verify_url_and_headers = URLHeaders(
                url=verify_dict["href"], headers=verify_dict["header"]
            )
            res.verify = verify_url_and_headers
    return res


def _upload_file_to_lfs_server(url_headers: URLHeaders, content: bytes):
    """
    Uploads file content to lfs server.
    :param url_headers: URL and headers returned by LFS server to upload.
    :param content: file content to upload.
    :return: None
    :raise AssertionError if the server doesn't return 200 status code.
    """

    url_headers.headers["Content-Type"] = "application/octet-stream"
    response = requests.put(
        headers=url_headers.headers, url=url_headers.url, data=content
    )
    assert response.status_code == 200, _error_message(response)


def _verify_file_uploaded(url_headers: URLHeaders, file_data: FileData):
    headers = url_headers.headers
    headers["Content-Type"] = "application/vnd.git-lfs+json"
    post_data = {"oid": file_data.digest, "size": file_data.size}
    response = requests.post(
        url=url_headers.url,
        headers=url_headers.headers,
        data=post_data,
    )
    assert response.status_code == 200, _error_message(response)


def _commit_file(
    gh_repo: GHRepo,
    path: str,
    content: str,
    branch: str,
    message: str,
):
    g = Github(gh_repo.token)
    repository: Repository = g.get_repo(gh_repo.name)

    maybe_content = _get_github_content(repository=repository, path=path, branch=branch)
    if maybe_content:  # if file exists in repository
        repository.update_file(
            path=maybe_content.path,
            message=message,
            content=content,
            sha=maybe_content.sha,
        )
    else:
        repository.create_file(
            path=path, message=message, content=content, branch=branch
        )


def _get_github_content(
    repository: Repository, path: str, branch: str
) -> Optional[ContentFile]:
    try:
        old_contents = repository.get_contents(path=path, ref=branch)
        if isinstance(old_contents, list):
            if not old_contents:
                return None
            old_content = old_contents[0]
        else:
            old_content = old_contents
    except UnknownObjectException:
        return None
    else:
        return old_content


def _error_message(response: requests.Response) -> str:
    return (
        f"Expected success, got {response.status_code} status code. \n{response.text}"
    )
