from abc import ABC, abstractmethod


class Hasher(ABC):
    @abstractmethod
    def update(self, inp: bytes) -> None:
        ...

    @abstractmethod
    def digest(self) -> bytes:
        ...

    def hexdigest(self) -> str:
        return self.digest().hex()

    @classmethod
    @abstractmethod
    def get_padding(cls, len_: int) -> bytes:
        ...
