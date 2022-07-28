import pytest
from sigma.backends.netwitness import NetwitnessBackend, NetwitnessEPLBackend
from sigma.collection import SigmaCollection

@pytest.fixture
def netwitness_backend():
    return NetwitnessBackend()
@pytest.fixture    
def netwitness_epl_backend():
    return NetwitnessEPLBackend()

# Testing for netwitness backend
def test_netwitness_in_expression(netwitness_backend : NetwitnessBackend):
    assert netwitness_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """),
    ) == ["fieldA='valueA'  ||  fieldA='valueB'  ||  fieldA begins 'valueC'"]

def test_netwitness_regex_query(netwitness_backend : NetwitnessBackend):
    assert netwitness_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """)
    ) == ["fieldA regex 'foo.*bar'  &&  fieldB='foo'  &&  fieldC='bar'"]

def test_netwitness_single_regex_query(netwitness_backend : NetwitnessBackend):
    assert netwitness_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                condition: sel
        """)
    ) == ["fieldA regex 'foo.*bar'"]

def test_netwitness_cidr_query(netwitness_backend : NetwitnessBackend):
    assert netwitness_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cidr: 192.168.0.0/16
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """)
    ) ==["fieldA = '192.168.0.0/16'  &&  fieldB='foo'  &&  fieldC='bar'"]


def test_netwitness_default_output(netwitness_backend : NetwitnessBackend):
    rules = """
title: Test 1
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA|re: foo.*bar
        fieldB: foo
        fieldC: bar
    condition: sel
---
title: Test 2
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: foo
        fieldB: bar
    condition: sel
    """
    assert netwitness_backend.convert(SigmaCollection.from_yaml(rules), ) == ["fieldA regex 'foo.*bar'  &&  fieldB='foo'  &&  fieldC='bar'", "fieldA='foo'  &&  fieldB='bar'"]



# Testing for netwitness epl backend
def test_netwitness_epl_in_expression(netwitness_epl_backend : NetwitnessEPLBackend):
    assert netwitness_epl_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """),
    ) == ["module Test;\n@Name('Test')\n@Description('Test\nReferences:\n- ')\n@RSAAlert(oneInSeconds=0) \nSELECT * FROM Event(\nfieldA = 'valueA'  OR  fieldA = 'valueB'  OR  fieldA like 'valueC%'\n);"]

def test_netwitness_epl_regex_query(netwitness_epl_backend : NetwitnessEPLBackend):
    assert netwitness_epl_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """)
    ) == ["module Test;\n@Name('Test')\n@Description('Test\nReferences:\n- ')\n@RSAAlert(oneInSeconds=0) \nSELECT * FROM Event(\nfieldA REGEXP 'foo.*bar'  AND  fieldB = 'foo'  AND  fieldC = 'bar'\n);"]

def test_netwitness_epl_single_regex_query(netwitness_epl_backend : NetwitnessEPLBackend):
    assert netwitness_epl_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                condition: sel
        """)
    ) == ["module Test;\n@Name('Test')\n@Description('Test\nReferences:\n- ')\n@RSAAlert(oneInSeconds=0) \nSELECT * FROM Event(\nfieldA REGEXP 'foo.*bar'\n);"]

def test_netwitness_epl_cidr_query(netwitness_epl_backend : NetwitnessEPLBackend):
    assert netwitness_epl_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cidr: 192.168.0.0/16
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """)
    ) ==["module Test;\n@Name('Test')\n@Description('Test\nReferences:\n- ')\n@RSAAlert(oneInSeconds=0) \nSELECT * FROM Event(\nfieldA = '192.168.0.0/16'  AND  fieldB = 'foo'  AND  fieldC = 'bar'\n);"]


def test_netwitness_epl_default_output(netwitness_epl_backend : NetwitnessEPLBackend):
    rules = """
title: Test 1
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA|re: foo.*bar
        fieldB: foo
        fieldC: bar
    condition: sel
---
title: Test 2
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: foo
        fieldB: bar
    condition: sel
    """
    assert netwitness_epl_backend.convert(SigmaCollection.from_yaml(rules), ) == ["module Test_1;\n@Name('Test_1')\n@Description('Test 1\nReferences:\n- ')\n@RSAAlert(oneInSeconds=0) \nSELECT * FROM Event(\nfieldA REGEXP 'foo.*bar'  AND  fieldB = 'foo'  AND  fieldC = 'bar'\n);", "module Test_2;\n@Name('Test_2')\n@Description('Test 2\nReferences:\n- ')\n@RSAAlert(oneInSeconds=0) \nSELECT * FROM Event(\nfieldA = 'foo'  AND  fieldB = 'bar'\n);"]



