__all__ = [
    "scanner"
]

from yaml.parser import Parser
from yaml.reader import Reader
from yaml.composer import Composer
from yaml.constructor import SafeConstructor
from yaml.resolver import Resolver

from .scanner import KnotScanner

class KnotYAMLLoader(Reader, KnotScanner, Parser, Composer, SafeConstructor, Resolver):
    def __init__(self, stream) -> None:
        Reader.__init__(self, stream)
        KnotScanner.__init__(self)
        Parser.__init__(self)
        Composer.__init__(self)
        SafeConstructor.__init__(self)
        Resolver.__init__(self)
