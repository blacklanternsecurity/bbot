from bbot.core.config.merge import deep_merge, dotted_get, dotted_set, iter_dotted_paths


# ----- deep_merge -----


def test_deep_merge_basic():
    assert deep_merge({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}


def test_deep_merge_last_wins():
    assert deep_merge({"a": 1}, {"a": 2}, {"a": 3}) == {"a": 3}


def test_deep_merge_recurses_into_dicts():
    a = {"web": {"timeout": 5, "user_agent": "x"}}
    b = {"web": {"timeout": 10}}
    assert deep_merge(a, b) == {"web": {"timeout": 10, "user_agent": "x"}}


def test_deep_merge_lists_are_replaced_not_concatenated():
    # Matches OmegaConf's REPLACE list-merge mode (BBOT's previous default).
    a = {"event_types": ["DNS_NAME", "URL"]}
    b = {"event_types": ["EMAIL_ADDRESS"]}
    assert deep_merge(a, b) == {"event_types": ["EMAIL_ADDRESS"]}


def test_deep_merge_dict_replaces_scalar():
    # Pydantic catches the resulting type mismatch downstream; merge itself
    # does the structural replacement without complaint.
    assert deep_merge({"a": 1}, {"a": {"b": 2}}) == {"a": {"b": 2}}


def test_deep_merge_scalar_replaces_dict():
    assert deep_merge({"a": {"b": 1}}, {"a": 5}) == {"a": 5}


def test_deep_merge_none_inputs():
    # All three forms used by callers in core.py / files.py
    assert deep_merge(None, {"a": 1}) == {"a": 1}
    assert deep_merge({"a": 1}, None) == {"a": 1}
    assert deep_merge(None, None) == {}


def test_deep_merge_no_aliasing_with_base():
    """Mutating the result must not affect the base dict."""
    a = {"web": {"headers": {"X-Foo": "1"}}}
    result = deep_merge(a, {})
    result["web"]["headers"]["X-Foo"] = "MUTATED"
    result["web"]["new_key"] = "new"
    assert a == {"web": {"headers": {"X-Foo": "1"}}}


def test_deep_merge_no_aliasing_with_update():
    """Mutating the result must not affect the update dict either."""
    b = {"web": {"headers": {"X-Foo": "1"}}}
    result = deep_merge({}, b)
    result["web"]["headers"]["X-Foo"] = "MUTATED"
    assert b == {"web": {"headers": {"X-Foo": "1"}}}


def test_deep_merge_no_aliasing_for_lists():
    """Lists in update should be deep-copied, not aliased."""
    b = {"event_types": ["DNS_NAME"]}
    result = deep_merge({}, b)
    result["event_types"].append("URL")
    assert b == {"event_types": ["DNS_NAME"]}


def test_deep_merge_empty_update_skipped():
    a = {"a": 1}
    assert deep_merge(a, {}) == {"a": 1}
    assert deep_merge(a, {}, {}, {"b": 2}) == {"a": 1, "b": 2}


# ----- dotted_get -----


def test_dotted_get_hit():
    assert dotted_get({"a": {"b": {"c": 1}}}, "a.b.c") == 1


def test_dotted_get_default_when_missing():
    assert dotted_get({"a": 1}, "a.b.c", default="x") == "x"


def test_dotted_get_default_when_blocked_by_scalar():
    # `a` exists but is a scalar, so `a.b` can't be resolved.
    assert dotted_get({"a": 1}, "a.b") is None
    assert dotted_get({"a": 1}, "a.b", default="fallback") == "fallback"


def test_dotted_get_top_level():
    assert dotted_get({"a": 1}, "a") == 1


# ----- dotted_set -----


def test_dotted_set_creates_intermediates():
    d = {}
    dotted_set(d, "a.b.c", 1)
    assert d == {"a": {"b": {"c": 1}}}


def test_dotted_set_preserves_siblings():
    d = {"a": {"b": 1}}
    dotted_set(d, "a.c", 2)
    assert d == {"a": {"b": 1, "c": 2}}


def test_dotted_set_overwrites_existing_leaf():
    d = {"a": {"b": 1}}
    dotted_set(d, "a.b", 99)
    assert d == {"a": {"b": 99}}


def test_dotted_set_silently_replaces_non_dict_intermediate():
    """
    Documented behavior: a scalar in the path is silently replaced by a dict.
    Pydantic validation downstream surfaces the resulting type mismatch.
    """
    d = {"a": 1}
    dotted_set(d, "a.b", 2)
    assert d == {"a": {"b": 2}}


def test_dotted_set_top_level():
    d = {}
    dotted_set(d, "a", 1)
    assert d == {"a": 1}


# ----- iter_dotted_paths -----


def test_iter_dotted_paths_basic():
    assert iter_dotted_paths({"a": 1, "b": {"c": 2}}) == ["a", "b.c"]


def test_iter_dotted_paths_deep():
    paths = iter_dotted_paths({"a": {"b": {"c": 1, "d": 2}}, "e": 3})
    assert sorted(paths) == ["a.b.c", "a.b.d", "e"]


def test_iter_dotted_paths_empty_dict_treated_as_leaf():
    # An empty dict is a leaf path so dotted_get/dotted_set round-trip through it.
    assert iter_dotted_paths({"a": {}, "b": 1}) == ["a", "b"]


def test_iter_dotted_paths_empty_input():
    assert iter_dotted_paths({}) == []


# ----- round-trip -----


def test_dotted_set_get_roundtrip():
    d = {}
    dotted_set(d, "modules.shodan.api_key", "abc123")
    dotted_set(d, "web.spider_distance", 2)
    assert dotted_get(d, "modules.shodan.api_key") == "abc123"
    assert dotted_get(d, "web.spider_distance") == 2
    assert sorted(iter_dotted_paths(d)) == ["modules.shodan.api_key", "web.spider_distance"]
