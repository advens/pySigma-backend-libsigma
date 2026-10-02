# SPDX-License-Identifier: LGPL-2.1-only
"""pySigma backend: one Sigma collection to one libsigma ruleset.

``convert()`` returns the ``.sigmac`` bytes, or the correlation JSON when
``output_format="corr"``. Per-condition query methods are not the artifact.
Buckets, the literal prefilter, and rule ids are properties of the whole
collection, so they are built in :func:`compile_rules`.
"""

from __future__ import annotations

import abc
from typing import Any, ClassVar

from sigma.conversion.base import Backend
from sigma.exceptions import SigmaBackendError
from sigma.rule import SigmaRule

from .compiler import compile_rules
from .correlation import correlations_to_json

_FRAGMENT = (
    "libsigma compiles a Sigma collection to one .sigmac artifact in "
    "convert(). A single condition is not a query."
)

_CONDITION_METHODS = (
    "convert_condition_as_in_expression",
    "convert_condition_or",
    "convert_condition_and",
    "convert_condition_not",
    "convert_condition_field_eq_val_str",
    "convert_condition_field_eq_val_str_case_sensitive",
    "convert_condition_field_eq_val_num",
    "convert_condition_field_eq_val_timestamp_part",
    "convert_condition_field_eq_val_bool",
    "convert_condition_field_eq_val_re",
    "convert_condition_field_eq_val_cidr",
    "convert_condition_field_compare_op_val",
    "convert_condition_field_eq_field",
    "convert_condition_field_eq_val_null",
    "convert_condition_field_exists",
    "convert_condition_field_not_exists",
    "convert_condition_field_eq_query_expr",
    "convert_condition_val_str",
    "convert_condition_val_num",
    "convert_condition_val_re",
    "convert_condition_query_expr",
    "convert_correlation_event_count_rule",
    "convert_correlation_extended_temporal_ordered_rule",
    "convert_correlation_extended_temporal_rule",
    "convert_correlation_temporal_ordered_rule",
    "convert_correlation_temporal_rule",
    "convert_correlation_value_avg_rule",
    "convert_correlation_value_count_rule",
    "convert_correlation_value_median_rule",
    "convert_correlation_value_percentile_rule",
    "convert_correlation_value_sum_rule",
)


def _refuse_fragment(self, *args, **kwargs):
    raise SigmaBackendError(_FRAGMENT)


class LibsigmaBackend(Backend):
    """Compile a Sigma collection to a libsigma ruleset.

    ``ecs=True`` (the default) renames SigmaHQ field names to ECS when the
    rule's taxonomy is ``sigma``, and leaves ``taxonomy: ecs`` rules alone.
    ``ecs=False`` compiles every field name as written. A processing pipeline
    passed to the constructor is applied before that rename.

    The last :class:`CompileResult` is kept on ``last_result`` (errors,
    dropped rules, warnings, the correlation objects).
    """

    name: ClassVar[str] = "libsigma"
    formats: ClassVar[dict[str, str]] = {
        "sigmac": "libsigma .sigmac ruleset (bytes, one artifact for the collection)",
        "corr": "libsigma rules.corr.json",
        "default": "libsigma .sigmac ruleset (bytes)",
    }
    default_format: ClassVar[str] = "sigmac"
    requires_pipeline: ClassVar[bool] = False

    def __init__(
        self,
        processing_pipeline=None,
        collect_errors: bool = False,
        ecs: bool = True,
        placeholders: dict | None = None,
        keep_deprecated: bool = False,
        **backend_options,
    ) -> None:
        super().__init__(
            processing_pipeline=processing_pipeline,
            collect_errors=collect_errors,
            **backend_options,
        )
        self.ecs = ecs
        self.placeholders = placeholders
        self.keep_deprecated = keep_deprecated
        self.last_result = None

    def convert(
        self,
        rule_collection,
        output_format: str | None = None,
        correlation_method: str | None = None,
        callback=None,
    ) -> Any:
        fmt = output_format or self.default_format
        if fmt not in self.formats:
            raise SigmaBackendError(f"unknown output format {fmt!r}")
        if self.processing_pipeline is not None:
            for rule in getattr(rule_collection, "rules", ()):
                if isinstance(rule, SigmaRule):
                    self.processing_pipeline.apply(rule)
        result = compile_rules(
            rule_collection,
            ecs=self.ecs,
            placeholders=self.placeholders,
            keep_deprecated=self.keep_deprecated,
        )
        self.last_result = result
        if fmt == "corr":
            return correlations_to_json(result.correlations)
        return result.artifact


for _name in _CONDITION_METHODS:
    setattr(LibsigmaBackend, _name, _refuse_fragment)
abc.update_abstractmethods(LibsigmaBackend)
