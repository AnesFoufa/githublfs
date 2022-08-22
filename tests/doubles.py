from dataclasses import dataclass


@dataclass(frozen=True)
class FakeGithubContent:
    path: str
    sha: str
