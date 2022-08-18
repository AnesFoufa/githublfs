Python Github LFS client
========================
githublfs is a Python library currently exposing a single method to upload and commit a file to a Github repository
using git LFS.

See https://git-lfs.github.com/

Usage
-----
>>> from githublfs import commit_lfs_file
>>> commit_lfs_file(repo="AnesFoufa/githublfs",
                    token="gh_token_with_repo_scope",
                    branch="main",
                    path="assets/logo.jpg",
                    content=b"binary file content",
                    message="my commit message")

To authenticate, an access token with repo scope is neede. See: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token

Dependencies
------------
* python = "^3.7"
* PyGithub = "^1.55"
* requests = "^2.28.1"

Implementation details
----------------------
This library uses LFS' Basic Transfer API. See https://github.com/git-lfs/git-lfs/blob/main/docs/api/basic-transfers.md

Production warning
------------------
This library is still experimental. If you use it in production, please pin the exact version in your requirements, including the minor number.