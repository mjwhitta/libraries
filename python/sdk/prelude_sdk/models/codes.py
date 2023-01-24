from enum import Enum, unique


class Colors(Enum):
    GREEN = 'green'
    RED = 'red'
    MAGENTA = 'magenta'


@unique
class RunCode(Enum):
    UNKNOWN = -1
    DEBUG = 0
    DAILY = 1
    WEEKLY = 2
    MONTHLY = 3
    ONCE = 4

    @classmethod
    def _missing_(cls, value):
        return RunCode.UNKNOWN

@unique
class Permission(Enum):
    UNKNOWN = -1
    ADMIN = 0
    EXECUTIVE = 1
    BUILD = 2
    SERVICE = 3

    @classmethod
    def _missing_(cls, value):
        return Permission.UNKNOWN

@unique
class Lookup(Enum):
    OTHER = -1
    ERROR = 1
    MALFORMED_VST = 2
    PROCESS_KILLED = 9
    PASSED = 100
    FAILED = 101
    TIMEOUT = 102
    CLEANUP_ERR = 103
    NOT_RELEVANT = 104
    QUARANTINED = 105
    INCOMPATIBLE_HOST = 126
    QUARANTINED_VST = 127
    UNEXPECTED = 256

    @classmethod
    def _missing_(cls, value):
        return Lookup.OTHER
