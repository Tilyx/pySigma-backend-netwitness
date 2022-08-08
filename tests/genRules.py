from sigma.backends.netwitness import NetwitnessBackend, NetwitnessEPLBackend
from sigma.collection import SigmaCollection


netwitness_Backend = NetwitnessEPLBackend()

rule = """
title: Test
status: test
logsource:
    product: windows
    service: security
detection:
    sel:
        CommandLine: test
    condition: sel
    """

a = netwitness_Backend.convert(SigmaCollection.from_yaml(rule), "default")
print(a[0])