from asyncio.events import AbstractEventLoop
from signal import Signals
from sys import stderr
from subprocess import Popen

# credits : https://stackoverflow.com/a/68732870


class SignalHaltError(SystemExit):
    def __init__(self, signal_enum: Signals):
        self.signal_enum = signal_enum
        print(repr(self), file=stderr)
        super().__init__(self.exit_code)

    @property
    def exit_code(self) -> int:
        return self.signal_enum.value

    def __repr__(self) -> str:
        return f"\nExitted due to {self.signal_enum.name}"


def immediate_exit(signal_enum: Signals, loop: AbstractEventLoop, p2p:Popen) -> None:
    p2p.terminate()
    loop.stop()
    raise SignalHaltError(signal_enum=signal_enum)
