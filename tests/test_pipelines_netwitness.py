import pytest
from sigma.collection import SigmaCollection
from sigma.backends.netwitness import NetwitnessBackend
from sigma.exceptions import SigmaTransformationError


def test_qradar_windows_pipeline_simple():
    assert NetwitnessBackend().convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: val1
                    Image: val2
                condition: sel
        """),"default"
    ) == ["param='val1'  &&  process='val2'"]

def test_qradar_pipeline_process_creation_field_mapping():
    assert NetwitnessBackend().convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    ProcessId: 1962
                    Image: 'Paint it Black'
                    OriginalFileName: 'Wild Horses'
                    CommandLine: "Jumpin' Jack Flash"
                    User: 'Mick Jagger'
                    ParentProcessId: 1972
                    ParentImage: 'Muddy Waters'
                condition: sel
        """),"default"
    ) == ["process.id.val=1962  &&  process='Paint it Black'  &&  process='Wild Horses'  &&  param='Jumpin' Jack Flash'  &&  user.dst='Mick Jagger'  &&  parent.pid.val=1972  &&  process.src='Muddy Waters'"]


def test_qradar_pipeline_web_proxy_field_mapping():
    assert NetwitnessBackend().convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: proxy
            detection:
                sel:
                    c-uri: 'https://www.thebeatles.com/'
                    c-uri-query: 'songs'
                    cs-method: GET
                    r-dns: 'www.thebeatles.com'
                    src_ip|cidr: 192.168.1.0/24
                    dst_ip: '54.229.169.162'
                condition: sel
        """)
    ) == ["c-uri='https://www.thebeatles.com/'  &&  c-uri-query='songs'  &&  cs-method='GET'  &&  r-dns='www.thebeatles.com'  &&  src_ip = '192.168.1.0/24'  &&  dst_ip='54.229.169.162'"]


def test_qradar_pipeline_unsupported_field_process_start():
    with pytest.raises(SigmaTransformationError, match="The RSA Netwitness & RSA Netwitness EPL Sigma backend supports only the following fields for windows log source, future will be update for Sysmon logsource and Linux"):
        NetwitnessBackend().convert(
            SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    sha1: val1
                    Image: val2
                condition: sel
            """),"default"
        )