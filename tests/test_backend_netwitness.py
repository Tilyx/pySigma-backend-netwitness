import pytest
from sigma.backends.netwitness import NetwitnessBackend

@pytest.fixture
def netwitness_backend():
    return NetwitnessBackend()

# TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# implemented with custom code, deferred expressions etc.



def test_netwitness_format1_output(netwitness_backend : NetwitnessBackend):
    """Test for output format format1."""
    # TODO: implement a test for the output format

def test_netwitness_format2_output(netwitness_backend : NetwitnessBackend):
    """Test for output format format2."""
    # TODO: implement a test for the output format

