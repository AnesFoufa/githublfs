from dataclasses import dataclass
from hashlib import sha256
from typing import Optional, Callable, Iterable, List

import requests
from github import Github, UnknownObjectException
from github.Repository import Repository
from github.ContentFile import ContentFile

__all__ = ["commit_lfs_file"]


def commit_lfs_file(
    repo: str, token: str, path: str, content: bytes, branch: str, message: str
):
    """
    Commits a file to a GitHub repository using LFS
    :param repo: Complete name of the GitHub repository. Example "AnesFoufa/githublfs"
    :param token: GitHub Personal access token with "repo" scope
    :param path: path to the file to commit. Example "assets/logo.jpg"
    :param content: Binary content of the file to update
    :param branch: Name of the branch to commit to. Example "main".
    :param message: Commit message. Example "update logo"
    :return: None
    """

    return _upload_and_commit(
        repository=repo,
        token=token,
        branch=branch,
        content=content,
        message=message,
        path=path,
    )


@dataclass(frozen=True)
class URLHeaders:
    url: str
    headers: dict


@dataclass
class UploadAndVerifyData:
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


class UploadAndCommitLFS:
    def __init__(self, upload_lfs, commit_pointer):
        self.upload_lfs = upload_lfs
        self.commit_pointer = commit_pointer

    def __call__(
        self,
        repository: str,
        token: str,
        path: str,
        content: bytes,
        branch: str,
        message: str,
    ):
        digest = self._hash_content(content)
        file_data = FileData(digest=digest, content=content)
        gh_repo = GHRepo(name=repository, token=token)

        self.upload_lfs(file_data=file_data, gh_repo=gh_repo)
        self.commit_pointer(
            gh_repo=gh_repo,
            file_data=file_data,
            branch=branch,
            message=message,
            path=path,
        )

    @staticmethod
    def _hash_content(content: bytes) -> str:
        hasher = sha256()
        hasher.update(content)
        return hasher.hexdigest()


class CheckUploadAndVerify:
    def __init__(
        self,
        check_uploaded: Callable[..., Optional[UploadAndVerifyData]],
        upload,
        verify,
    ):
        self.check_uploaded = check_uploaded
        self.upload = upload
        self.verify = verify

    def __call__(
        self,
        file_data: FileData,
        gh_repo: GHRepo,
    ):
        upload_and_verify_data = self.check_uploaded(
            file_data=file_data, gh_repo=gh_repo
        )
        if upload_and_verify_data:
            self.upload(
                url_headers=upload_and_verify_data.upload, content=file_data.content
            )
            if upload_and_verify_data.verify:
                self.verify(
                    url_headers=upload_and_verify_data.verify, file_data=file_data
                )


class CheckFileInLFSServer:
    def __init__(
        self,
        request_file_in_server: Callable[..., dict],
        parse_response: Callable[..., Optional[UploadAndVerifyData]],
    ):
        self.file_in_server = request_file_in_server
        self.parse_response = parse_response

    def __call__(
        self, gh_repo: GHRepo, file_data: FileData
    ) -> Optional[UploadAndVerifyData]:
        response = self.file_in_server(gh_repo=gh_repo, file_data=file_data)
        return self.parse_response(response=response)


class CommitLFSPointer:
    def __init__(self, commit_file: Callable[..., None]):
        self._commit_file = commit_file

    def __call__(
        self, gh_repo: GHRepo, file_data: FileData, message: str, path: str, branch: str
    ):
        pointer_content = (
            f"version https://git-lfs.github.com/spec/v1"
            f"\noid sha256:{file_data.digest}\nsize {file_data.size}\n"
        )
        self._commit_file(
            gh_repo=gh_repo,
            path=path,
            content=pointer_content,
            branch=branch,
            message=message,
        )


class CommitFile:
    def __init__(
        self, get_file_content: Callable[..., Optional[Iterable[ContentFile]]]
    ):
        self._get_file_content = get_file_content

    def __call__(
        self,
        gh_repo: GHRepo,
        path: str,
        content: str,
        branch: str,
        message: str,
    ):
        g = Github(gh_repo.token)
        repository: Repository = g.get_repo(full_name_or_id=gh_repo.name)

        maybe_contents = self._get_file_content(
            repository=repository, path=path, branch=branch
        )
        if maybe_contents is not None:  # if file exists in repository
            for file_content in maybe_contents:
                repository.update_file(
                    path=file_content.path,
                    message=message,
                    content=content,
                    sha=file_content.sha,
                    branch=branch,
                )
        else:
            repository.create_file(
                path=path, message=message, content=content, branch=branch
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


def _parse_upload_and_verify_from_response(
    response,
) -> Optional[UploadAndVerifyData]:
    first_object = response["objects"][0]
    res = None
    if "actions" in first_object and "upload" in first_object["actions"]:
        actions_dict = first_object["actions"]
        upload_dict = actions_dict["upload"]
        upload_url_and_headers = URLHeaders(
            headers=upload_dict["header"], url=upload_dict["href"]
        )
        res = UploadAndVerifyData(upload=upload_url_and_headers)
        if "verify" in actions_dict:
            verify_dict = actions_dict["verify"]
            verify_url_and_headers = URLHeaders(
                url=verify_dict["href"], headers=verify_dict["header"]
            )
            res.verify = verify_url_and_headers
    return res


def _upload_file_to_lfs_server(url_headers: URLHeaders, content: bytes):
    """
    Uploads file content to lfs server
    :param url_headers: URL and headers returned by LFS server to upload
    :param content: file content to upload.
    :return: None
    :raise AssertionError if the server doesn't return 200 status code.
    """
    headers = url_headers.headers.copy()
    headers["Content-Type"] = "application/octet-stream"
    response = requests.put(headers=headers, url=url_headers.url, data=content)
    assert response.status_code == 200, _error_message(response)


def _verify_file_uploaded(url_headers: URLHeaders, file_data: FileData):
    headers = url_headers.headers.copy()
    headers["Content-Type"] = "application/vnd.git-lfs+json"
    post_data = {"oid": file_data.digest, "size": file_data.size}
    response = requests.post(
        url=url_headers.url,
        headers=headers,
        data=post_data,
    )
    assert response.status_code == 200, _error_message(response)


def _get_github_content(
    repository: Repository, path: str, branch: str
) -> Optional[List[ContentFile]]:
    try:
        old_contents = repository.get_contents(path=path, ref=branch)
        if isinstance(old_contents, list):
            res = old_contents
        else:
            res = [old_contents]
    except UnknownObjectException:
        res = None
    return res


def _error_message(response: requests.Response) -> str:
    return (
        f"Expected success, got {response.status_code} status code. \n{response.text}"
    )


_upload_lfs = CheckUploadAndVerify(
    check_uploaded=CheckFileInLFSServer(
        request_file_in_server=_post_pre_upload_request_to_lfs_server,
        parse_response=_parse_upload_and_verify_from_response,
    ),
    upload=_upload_file_to_lfs_server,
    verify=_verify_file_uploaded,
)
_upload_and_commit = UploadAndCommitLFS(
    upload_lfs=_upload_lfs,
    commit_pointer=CommitLFSPointer(
        commit_file=CommitFile(get_file_content=_get_github_content)
    ),
)
