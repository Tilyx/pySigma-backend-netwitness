from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from collections import defaultdict
from sigma.processing.pipeline import ProcessingPipeline
from sigma.conversion.base import TextQueryBackend
from sigma.types import SigmaCompareExpression
from sigma.pipelines.netwitness import netwitness_windows
import sigma
from typing import ClassVar, Dict, List, Optional, Tuple
# requirements

# Netwitness Backend build base on Splunk Backend 
# Author: Duc.Le - Tilyx Team
# Supporting: ...


class NetwitnessBackend(TextQueryBackend):
    """RSA Netwitness backend."""
    group_expression : ClassVar[str] = "({expr})"

    or_token : ClassVar[str] = " || "
    and_token : ClassVar[str] = " && "
    not_token : ClassVar[str] = "NOT"
    eq_token : ClassVar[str] = "="
    field_quote: ClassVar[str] =""
    str_quote : ClassVar[str] = "'"
    escape_char : ClassVar[str] = ""
    wildcard_multi : ClassVar[str]= "*"
    wildcard_single : ClassVar[str] = "*"
    add_escaped : ClassVar[str] = ""

    re_expression : ClassVar[str] = "{field} regex '{regex}'"
    re_escape_char : ClassVar[str] = ""
    re_escape : ClassVar[Tuple[str]] = ('"',)


    cidr_expression : ClassVar[str] = "{field} = '{value}'" 
    startswith_expression : ClassVar[str] = "{field} begins '{value}'"
    endswith_expression   : ClassVar[str] = "{field} ends '{value}'"
    contains_expression   : ClassVar[str] = "{field} contains '{value}'"

    compare_op_expression : ClassVar[str] = "{field} {operator} {value}"

    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    field_null_expression : ClassVar[str] = "{field} !exists"
    # Need testing
    convert_or_as_in : ClassVar[bool] = False
    convert_and_as_in : ClassVar[bool] = False
    in_expressions_allow_wildcards : ClassVar[bool] = True
    field_in_list_expression : ClassVar[str] = "{field} {op} {list}" # Need tune performance
    or_in_operator : ClassVar[Optional[str]] = "regex"
    list_separator : ClassVar[str] = ","

    unbound_value_str_expression : ClassVar[str] = "'{value}'"
    unbound_value_num_expression : ClassVar[str] = '{value}'
    unbound_value_re_expression : ClassVar[str] = '{value}'
    deferred_start : ClassVar[str] = ""
    deferred_separator : ClassVar[str] = ""
    deferred_only_query : ClassVar[str] = ""

    output_format_processing_pipeline = defaultdict(ProcessingPipeline,
    # Mapping rules
        default = netwitness_windows()
    )

    def __init__(self, processing_pipeline: Optional["sigma.processing.pipeline.ProcessingPipeline"] = None, collect_errors: bool = False, **kwargs):
        super().__init__(processing_pipeline, collect_errors, **kwargs)


    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        netwitness_prefix = ""
        escaped_query = " \\\n".join(query.split("\n"))      # escape line ends for multiline queries
        netwitness_prefix += escaped_query
        # print(netwitness_prefix)
        return netwitness_prefix



class NetwitnessEPLBackend(TextQueryBackend):
    """RSA Netwitness EPL Rules backend."""

    group_expression : ClassVar[str] = "({expr})"

    or_token : ClassVar[str] = " OR "
    and_token : ClassVar[str] = " AND "
    not_token : ClassVar[str] = "NOT"
    eq_token : ClassVar[str] = " = "
    field_quote: ClassVar[str] =""
    str_quote : ClassVar[str] = "'"
    escape_char : ClassVar[str] = ""
    wildcard_multi : ClassVar[str] = "%"
    wildcard_single : ClassVar[str] = "%"
    add_escaped : ClassVar[str] = ""

    re_expression : ClassVar[str] = "{field} REGEXP '{regex}'"
    re_escape_char : ClassVar[str] = ""
    re_escape : ClassVar[Tuple[str]] = ('"',)


    cidr_expression : ClassVar[str] = "{field} = '{value}'" 
    startswith_expression : ClassVar[str] = "{field} like '{value}%'"
    endswith_expression   : ClassVar[str] = "{field} like '%{value}'"
    contains_expression   : ClassVar[str] = "{field} like '%{value}%'"

    compare_op_expression : ClassVar[str] = "{field} {operator} {value}"

    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    field_null_expression : ClassVar[str] = "{field} is null"
    # Need testing
    convert_or_as_in : ClassVar[bool] = False
    convert_and_as_in : ClassVar[bool] = False
    in_expressions_allow_wildcards : ClassVar[bool] = True
    # field_in_list_expression : ClassVar[str] = "{field} {op} {list}" # Need tune performance
    # or_in_operator : ClassVar[Optional[str]] = "regex"
    # list_separator : ClassVar[str] = ","

    unbound_value_str_expression : ClassVar[str] = "'{value}'"
    unbound_value_num_expression : ClassVar[str] = '{value}'
    unbound_value_re_expression : ClassVar[str] = '{value}'
    deferred_start : ClassVar[str] = ""
    deferred_separator : ClassVar[str] = ""
    deferred_only_query : ClassVar[str] = ""

    output_format_processing_pipeline = defaultdict(ProcessingPipeline,
    # Mapping rules
        default = netwitness_windows()
    )

    def __init__(self, processing_pipeline: Optional["sigma.processing.pipeline.ProcessingPipeline"] = None, collect_errors: bool = False, **kwargs):
        super().__init__(processing_pipeline, collect_errors, **kwargs)


    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        if rule.description == None:
            rule.description = rule.title
        self.description =  rule.description + "\nReferences:\n- "+"\n- ".join(rule.references)
        self.title = rule.title.replace(" ","_")      
        netwitness_prefix = ""
        escaped_query = " \\\n".join(query.split("\n"))      # escape line ends for multiline queries
        netwitness_prefix += escaped_query
        return         f"""module {self.title};
@Name('{self.title}')
@Description('{self.description}')
@RSAAlert(oneInSeconds=0) 
SELECT * FROM Event(
{netwitness_prefix}
);"""
    def finalize_output_default(self, queries: List[str]) -> str:
        return queries
