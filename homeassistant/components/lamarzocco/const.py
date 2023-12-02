"""Constants for the La Marzocco integration."""

from typing import Final

DOMAIN: Final = "lamarzocco"

POLLING_INTERVAL: Final = 30

GLOBAL: Final = "global"
MON: Final = "mon"
TUE: Final = "tue"
WED: Final = "wed"
THU: Final = "thu"
FRI: Final = "fri"
SAT: Final = "sat"
SUN: Final = "sun"

DAYS: Final = [MON, TUE, WED, THU, FRI, SAT, SUN]

CONF_MACHINE: Final = "machine"
CONF_USE_BLUETOOTH: Final = "use_bluetooth"
