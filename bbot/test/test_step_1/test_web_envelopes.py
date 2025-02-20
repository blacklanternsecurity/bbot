import pytest


async def test_web_envelopes():
    from bbot.core.helpers.web.envelopes import (
        BaseEnvelope,
        TextEnvelope,
        HexEnvelope,
        B64Envelope,
        JSONEnvelope,
        XMLEnvelope,
        URLEnvelope,
    )

    # simple text
    text_envelope = BaseEnvelope.detect("foo")
    assert isinstance(text_envelope, TextEnvelope)
    assert text_envelope.unpacked_data() == "foo"
    assert text_envelope.subparams == {"__default__": "foo"}
    expected_subparams = [([], "foo")]
    assert list(text_envelope.get_subparams()) == expected_subparams
    for subparam, value in expected_subparams:
        assert text_envelope.get_subparam(subparam) == value
    assert text_envelope.pack() == "foo"
    assert text_envelope.num_envelopes == 0
    assert text_envelope.get_subparam() == "foo"
    text_envelope.set_subparam(value="bar")
    assert text_envelope.get_subparam() == "bar"
    assert text_envelope.unpacked_data() == "bar"

    # simple binary
    # binary_envelope = BaseEnvelope.detect("foo\x00")
    # assert isinstance(binary_envelope, BinaryEnvelope)
    # assert binary_envelope.unpacked_data == "foo\x00"
    # assert binary_envelope.packed_data == "foo\x00"
    # assert binary_envelope.subparams == {"__default__": "foo\x00"}

    # text encoded as hex
    hex_envelope = BaseEnvelope.detect("706172616d")
    assert isinstance(hex_envelope, HexEnvelope)
    assert hex_envelope.unpacked_data(recursive=True) == "param"
    hex_inner_envelope = hex_envelope.unpacked_data(recursive=False)
    assert isinstance(hex_inner_envelope, TextEnvelope)
    assert hex_inner_envelope.unpacked_data(recursive=False) == "param"
    assert hex_inner_envelope.unpacked_data(recursive=True) == "param"
    assert list(hex_envelope.get_subparams(recursive=False)) == [([], hex_inner_envelope)]
    assert list(hex_envelope.get_subparams(recursive=True)) == [([], "param")]
    assert hex_inner_envelope.unpacked_data() == "param"
    assert hex_inner_envelope.subparams == {"__default__": "param"}
    expected_subparams = [([], "param")]
    assert list(hex_inner_envelope.get_subparams()) == expected_subparams
    for subparam, value in expected_subparams:
        assert hex_inner_envelope.get_subparam(subparam) == value
    assert hex_envelope.pack() == "706172616d"
    assert hex_envelope.num_envelopes == 1
    assert hex_envelope.get_subparam() == "param"
    hex_envelope.set_subparam(value="asdf")
    assert hex_envelope.get_subparam() == "asdf"
    assert hex_envelope.unpacked_data() == "asdf"
    assert hex_envelope.pack() == "61736466"

    # text encoded as base64
    base64_envelope = BaseEnvelope.detect("cGFyYW0=")
    assert isinstance(base64_envelope, B64Envelope)
    assert base64_envelope.unpacked_data() == "param"
    base64_inner_envelope = base64_envelope.unpacked_data(recursive=False)
    assert isinstance(base64_inner_envelope, TextEnvelope)
    assert list(base64_envelope.get_subparams(recursive=False)) == [([], base64_inner_envelope)]
    assert list(base64_envelope.get_subparams()) == [([], "param")]
    assert base64_inner_envelope.pack() == "param"
    assert base64_inner_envelope.unpacked_data() == "param"
    assert base64_inner_envelope.subparams == {"__default__": "param"}
    expected_subparams = [([], "param")]
    assert list(base64_inner_envelope.get_subparams()) == expected_subparams
    for subparam, value in expected_subparams:
        assert base64_inner_envelope.get_subparam(subparam) == value
    assert base64_envelope.num_envelopes == 1
    base64_envelope.set_subparam(value="asdf")
    assert base64_envelope.get_subparam() == "asdf"
    assert base64_envelope.unpacked_data() == "asdf"
    assert base64_envelope.pack() == "YXNkZg=="

    # test inside hex inside base64
    hex_envelope = BaseEnvelope.detect("634746795957303d")
    assert isinstance(hex_envelope, HexEnvelope)
    assert hex_envelope.get_subparam() == "param"
    assert hex_envelope.unpacked_data() == "param"
    base64_envelope = hex_envelope.unpacked_data(recursive=False)
    assert isinstance(base64_envelope, B64Envelope)
    assert base64_envelope.get_subparam() == "param"
    assert base64_envelope.unpacked_data() == "param"
    text_envelope = base64_envelope.unpacked_data(recursive=False)
    assert isinstance(text_envelope, TextEnvelope)
    assert text_envelope.get_subparam() == "param"
    assert text_envelope.unpacked_data() == "param"
    hex_envelope.set_subparam(value="asdf")
    assert hex_envelope.get_subparam() == "asdf"
    assert hex_envelope.unpacked_data() == "asdf"
    assert text_envelope.get_subparam() == "asdf"
    assert text_envelope.unpacked_data() == "asdf"
    assert base64_envelope.get_subparam() == "asdf"
    assert base64_envelope.unpacked_data() == "asdf"

    # URL-encoded text
    url_encoded_envelope = BaseEnvelope.detect("a%20b%20c")
    assert isinstance(url_encoded_envelope, URLEnvelope)
    assert url_encoded_envelope.pack() == "a%20b%20c"
    assert url_encoded_envelope.unpacked_data() == "a b c"
    url_inner_envelope = url_encoded_envelope.unpacked_data(recursive=False)
    assert isinstance(url_inner_envelope, TextEnvelope)
    assert url_inner_envelope.unpacked_data(recursive=False) == "a b c"
    assert url_inner_envelope.unpacked_data(recursive=True) == "a b c"
    assert list(url_encoded_envelope.get_subparams(recursive=False)) == [([], url_inner_envelope)]
    assert list(url_encoded_envelope.get_subparams(recursive=True)) == [([], "a b c")]
    assert url_inner_envelope.pack() == "a b c"
    assert url_inner_envelope.unpacked_data() == "a b c"
    assert url_inner_envelope.subparams == {"__default__": "a b c"}
    expected_subparams = [([], "a b c")]
    assert list(url_inner_envelope.get_subparams()) == expected_subparams
    for subparam, value in expected_subparams:
        assert url_inner_envelope.get_subparam(subparam) == value
    assert url_encoded_envelope.num_envelopes == 1
    url_encoded_envelope.set_subparam(value="a s d f")
    assert url_encoded_envelope.get_subparam() == "a s d f"
    assert url_encoded_envelope.unpacked_data() == "a s d f"
    assert url_encoded_envelope.pack() == "a%20s%20d%20f"

    # json
    json_envelope = BaseEnvelope.detect('{"param1": "val1", "param2": {"param3": "val3"}}')
    assert isinstance(json_envelope, JSONEnvelope)
    assert json_envelope.pack() == '{"param1": "val1", "param2": {"param3": "val3"}}'
    assert json_envelope.unpacked_data() == {"param1": "val1", "param2": {"param3": "val3"}}
    assert json_envelope.unpacked_data(recursive=False) == {"param1": "val1", "param2": {"param3": "val3"}}
    assert json_envelope.unpacked_data(recursive=True) == {"param1": "val1", "param2": {"param3": "val3"}}
    assert json_envelope.subparams == {"param1": "val1", "param2": {"param3": "val3"}}
    expected_subparams = [
        (["param1"], "val1"),
        (["param2", "param3"], "val3"),
    ]
    assert list(json_envelope.get_subparams()) == expected_subparams
    for subparam, value in expected_subparams:
        assert json_envelope.get_subparam(subparam) == value
    json_envelope.selected_subparam = ["param2", "param3"]
    assert json_envelope.get_subparam() == "val3"
    assert json_envelope.num_envelopes == 1

    # prevent json over-detection
    just_a_string = BaseEnvelope.detect("10")
    assert not isinstance(just_a_string, JSONEnvelope)

    # xml
    xml_envelope = BaseEnvelope.detect(
        '<root><param1 attr="attr1">val1</param1><param2><param3>val3</param3></param2></root>'
    )
    assert isinstance(xml_envelope, XMLEnvelope)
    assert (
        xml_envelope.pack()
        == '<?xml version="1.0" encoding="utf-8"?>\n<root><param1 attr="attr1">val1</param1><param2><param3>val3</param3></param2></root>'
    )
    assert xml_envelope.unpacked_data() == {
        "root": {"param1": {"@attr": "attr1", "#text": "val1"}, "param2": {"param3": "val3"}}
    }
    assert xml_envelope.unpacked_data(recursive=False) == {
        "root": {"param1": {"@attr": "attr1", "#text": "val1"}, "param2": {"param3": "val3"}}
    }
    assert xml_envelope.unpacked_data(recursive=True) == {
        "root": {"param1": {"@attr": "attr1", "#text": "val1"}, "param2": {"param3": "val3"}}
    }
    assert xml_envelope.subparams == {
        "root": {"param1": {"@attr": "attr1", "#text": "val1"}, "param2": {"param3": "val3"}}
    }
    expected_subparams = [
        (["root", "param1", "@attr"], "attr1"),
        (["root", "param1", "#text"], "val1"),
        (["root", "param2", "param3"], "val3"),
    ]
    assert list(xml_envelope.get_subparams()) == expected_subparams
    for subparam, value in expected_subparams:
        assert xml_envelope.get_subparam(subparam) == value
    assert xml_envelope.num_envelopes == 1

    # json inside base64
    base64_json_envelope = BaseEnvelope.detect("eyJwYXJhbTEiOiAidmFsMSIsICJwYXJhbTIiOiB7InBhcmFtMyI6ICJ2YWwzIn19")
    assert isinstance(base64_json_envelope, B64Envelope)
    assert base64_json_envelope.pack() == "eyJwYXJhbTEiOiAidmFsMSIsICJwYXJhbTIiOiB7InBhcmFtMyI6ICJ2YWwzIn19"
    assert base64_json_envelope.unpacked_data() == {"param1": "val1", "param2": {"param3": "val3"}}
    base64_inner_envelope = base64_json_envelope.unpacked_data(recursive=False)
    assert isinstance(base64_inner_envelope, JSONEnvelope)
    assert base64_inner_envelope.pack() == '{"param1": "val1", "param2": {"param3": "val3"}}'
    assert base64_inner_envelope.unpacked_data() == {"param1": "val1", "param2": {"param3": "val3"}}
    assert base64_inner_envelope.subparams == {"param1": "val1", "param2": {"param3": "val3"}}
    expected_subparams = [
        (["param1"], "val1"),
        (["param2", "param3"], "val3"),
    ]
    assert list(base64_json_envelope.get_subparams()) == expected_subparams
    for subparam, value in expected_subparams:
        assert base64_json_envelope.get_subparam(subparam) == value
    assert base64_json_envelope.num_envelopes == 2
    with pytest.raises(ValueError):
        assert base64_json_envelope.get_subparam()
    base64_json_envelope.selected_subparam = ["param2", "param3"]
    assert base64_json_envelope.get_subparam() == "val3"

    # xml inside url inside hex inside base64
    nested_xml_envelope = BaseEnvelope.detect(
        "MjUzMzYzMjUzNzMyMjUzNjY2MjUzNjY2MjUzNzM0MjUzMzY1MjUzMzYzMjUzNzMwMjUzNjMxMjUzNzMyMjUzNjMxMjUzNjY0MjUzMzMxMjUzMjMwMjUzNjMxMjUzNzM0MjUzNzM0MjUzNzMyMjUzMzY0MjUzMjMyMjUzNzM2MjUzNjMxMjUzNjYzMjUzMzMxMjUzMjMyMjUzMzY1MjUzNzM2MjUzNjMxMjUzNjYzMjUzMzMxMjUzMzYzMjUzMjY2MjUzNzMwMjUzNjMxMjUzNzMyMjUzNjMxMjUzNjY0MjUzMzMxMjUzMzY1MjUzMzYzMjUzNzMwMjUzNjMxMjUzNzMyMjUzNjMxMjUzNjY0MjUzMzMyMjUzMzY1MjUzMzYzMjUzNzMwMjUzNjMxMjUzNzMyMjUzNjMxMjUzNjY0MjUzMzMzMjUzMzY1MjUzNzM2MjUzNjMxMjUzNjYzMjUzMzMzMjUzMzYzMjUzMjY2MjUzNzMwMjUzNjMxMjUzNzMyMjUzNjMxMjUzNjY0MjUzMzMzMjUzMzY1MjUzMzYzMjUzMjY2MjUzNzMwMjUzNjMxMjUzNzMyMjUzNjMxMjUzNjY0MjUzMzMyMjUzMzY1MjUzMzYzMjUzMjY2MjUzNzMyMjUzNjY2MjUzNjY2MjUzNzM0MjUzMzY1"
    )
    assert isinstance(nested_xml_envelope, B64Envelope)
    assert nested_xml_envelope.unpacked_data() == {
        "root": {"param1": {"@attr": "val1", "#text": "val1"}, "param2": {"param3": "val3"}}
    }
    assert (
        nested_xml_envelope.pack()
        == "MjUzMzQzMjUzMzQ2Nzg2ZDZjMjUzMjMwNzY2NTcyNzM2OTZmNmUyNTMzNDQyNTMyMzIzMTJlMzAyNTMyMzIyNTMyMzA2NTZlNjM2ZjY0Njk2ZTY3MjUzMzQ0MjUzMjMyNzU3NDY2MmQzODI1MzIzMjI1MzM0NjI1MzM0NTI1MzA0MTI1MzM0MzcyNmY2Zjc0MjUzMzQ1MjUzMzQzNzA2MTcyNjE2ZDMxMjUzMjMwNjE3NDc0NzIyNTMzNDQyNTMyMzI3NjYxNmMzMTI1MzIzMjI1MzM0NTc2NjE2YzMxMjUzMzQzMmY3MDYxNzI2MTZkMzEyNTMzNDUyNTMzNDM3MDYxNzI2MTZkMzIyNTMzNDUyNTMzNDM3MDYxNzI2MTZkMzMyNTMzNDU3NjYxNmMzMzI1MzM0MzJmNzA2MTcyNjE2ZDMzMjUzMzQ1MjUzMzQzMmY3MDYxNzI2MTZkMzIyNTMzNDUyNTMzNDMyZjcyNmY2Zjc0MjUzMzQ1"
    )
    inner_hex_envelope = nested_xml_envelope.unpacked_data(recursive=False)
    assert isinstance(inner_hex_envelope, HexEnvelope)
    assert (
        inner_hex_envelope.pack()
        == "253343253346786d6c25323076657273696f6e253344253232312e30253232253230656e636f64696e672533442532327574662d38253232253346253345253041253343726f6f74253345253343706172616d312532306174747225334425323276616c3125323225334576616c312533432f706172616d31253345253343706172616d32253345253343706172616d3325334576616c332533432f706172616d332533452533432f706172616d322533452533432f726f6f74253345"
    )
    inner_url_envelope = inner_hex_envelope.unpacked_data(recursive=False)
    assert isinstance(inner_url_envelope, URLEnvelope)
    assert (
        inner_url_envelope.pack()
        == r"%3C%3Fxml%20version%3D%221.0%22%20encoding%3D%22utf-8%22%3F%3E%0A%3Croot%3E%3Cparam1%20attr%3D%22val1%22%3Eval1%3C/param1%3E%3Cparam2%3E%3Cparam3%3Eval3%3C/param3%3E%3C/param2%3E%3C/root%3E"
    )
    inner_xml_envelope = inner_url_envelope.unpacked_data(recursive=False)
    assert isinstance(inner_xml_envelope, XMLEnvelope)
    assert (
        inner_xml_envelope.pack()
        == '<?xml version="1.0" encoding="utf-8"?>\n<root><param1 attr="val1">val1</param1><param2><param3>val3</param3></param2></root>'
    )
    assert inner_xml_envelope.unpacked_data() == {
        "root": {"param1": {"@attr": "val1", "#text": "val1"}, "param2": {"param3": "val3"}}
    }
    assert inner_xml_envelope.subparams == {
        "root": {"param1": {"@attr": "val1", "#text": "val1"}, "param2": {"param3": "val3"}}
    }
    expected_subparams = [
        (["root", "param1", "@attr"], "val1"),
        (["root", "param1", "#text"], "val1"),
        (["root", "param2", "param3"], "val3"),
    ]
    assert list(nested_xml_envelope.get_subparams()) == expected_subparams
    for subparam, value in expected_subparams:
        assert nested_xml_envelope.get_subparam(subparam) == value
    assert nested_xml_envelope.num_envelopes == 4

    # manipulating text inside hex
    hex_envelope = BaseEnvelope.detect("706172616d")
    expected_subparams = [([], "param")]
    assert list(hex_envelope.get_subparams()) == expected_subparams
    for subparam, value in expected_subparams:
        assert hex_envelope.get_subparam(subparam) == value
    hex_envelope.set_subparam([], "asdf")
    expected_subparams = [([], "asdf")]
    assert list(hex_envelope.get_subparams()) == expected_subparams
    for subparam, value in expected_subparams:
        assert hex_envelope.get_subparam(subparam) == value
    assert hex_envelope.unpacked_data() == "asdf"

    # manipulating json inside base64
    base64_json_envelope = BaseEnvelope.detect("eyJwYXJhbTEiOiAidmFsMSIsICJwYXJhbTIiOiB7InBhcmFtMyI6ICJ2YWwzIn19")
    expected_subparams = [
        (["param1"], "val1"),
        (["param2", "param3"], "val3"),
    ]
    assert list(base64_json_envelope.get_subparams()) == expected_subparams
    for subparam, value in expected_subparams:
        assert base64_json_envelope.get_subparam(subparam) == value
    base64_json_envelope.set_subparam(["param1"], {"asdf": [None], "fdsa": 1.0})
    expected_subparams = [
        (["param1", "asdf"], [None]),
        (["param1", "fdsa"], 1.0),
        (["param2", "param3"], "val3"),
    ]
    assert list(base64_json_envelope.get_subparams()) == expected_subparams
    for subparam, value in expected_subparams:
        assert base64_json_envelope.get_subparam(subparam) == value
    base64_json_envelope.set_subparam(["param2", "param3"], {"1234": [None], "4321": 1.0})
    expected_subparams = [
        (["param1", "asdf"], [None]),
        (["param1", "fdsa"], 1.0),
        (["param2", "param3", "1234"], [None]),
        (["param2", "param3", "4321"], 1.0),
    ]
    assert list(base64_json_envelope.get_subparams()) == expected_subparams
    base64_json_envelope.set_subparam(["param2"], None)
    expected_subparams = [
        (["param1", "asdf"], [None]),
        (["param1", "fdsa"], 1.0),
        (["param2"], None),
    ]
    assert list(base64_json_envelope.get_subparams()) == expected_subparams

    # xml inside url inside base64
    xml_envelope = BaseEnvelope.detect(
        "JTNDP3htbCUyMHZlcnNpb249JTIyMS4wJTIyJTIwZW5jb2Rpbmc9JTIydXRmLTglMjI/JTNFJTBBJTNDcm9vdCUzRSUzQ3BhcmFtMSUyMGF0dHI9JTIydmFsMSUyMiUzRXZhbDElM0MvcGFyYW0xJTNFJTNDcGFyYW0yJTNFJTNDcGFyYW0zJTNFdmFsMyUzQy9wYXJhbTMlM0UlM0MvcGFyYW0yJTNFJTNDL3Jvb3QlM0U="
    )
    assert (
        xml_envelope.pack()
        == "JTNDJTNGeG1sJTIwdmVyc2lvbiUzRCUyMjEuMCUyMiUyMGVuY29kaW5nJTNEJTIydXRmLTglMjIlM0YlM0UlMEElM0Nyb290JTNFJTNDcGFyYW0xJTIwYXR0ciUzRCUyMnZhbDElMjIlM0V2YWwxJTNDL3BhcmFtMSUzRSUzQ3BhcmFtMiUzRSUzQ3BhcmFtMyUzRXZhbDMlM0MvcGFyYW0zJTNFJTNDL3BhcmFtMiUzRSUzQy9yb290JTNF"
    )
    expected_subparams = [
        (["root", "param1", "@attr"], "val1"),
        (["root", "param1", "#text"], "val1"),
        (["root", "param2", "param3"], "val3"),
    ]
    assert list(xml_envelope.get_subparams()) == expected_subparams
    xml_envelope.set_subparam(["root", "param1", "@attr"], "asdf")
    expected_subparams = [
        (["root", "param1", "@attr"], "asdf"),
        (["root", "param1", "#text"], "val1"),
        (["root", "param2", "param3"], "val3"),
    ]
    assert list(xml_envelope.get_subparams()) == expected_subparams
    assert (
        xml_envelope.pack()
        == "JTNDJTNGeG1sJTIwdmVyc2lvbiUzRCUyMjEuMCUyMiUyMGVuY29kaW5nJTNEJTIydXRmLTglMjIlM0YlM0UlMEElM0Nyb290JTNFJTNDcGFyYW0xJTIwYXR0ciUzRCUyMmFzZGYlMjIlM0V2YWwxJTNDL3BhcmFtMSUzRSUzQ3BhcmFtMiUzRSUzQ3BhcmFtMyUzRXZhbDMlM0MvcGFyYW0zJTNFJTNDL3BhcmFtMiUzRSUzQy9yb290JTNF"
    )
    xml_envelope.set_subparam(["root", "param2", "param3"], {"1234": [None], "4321": 1.0})
    expected_subparams = [
        (["root", "param1", "@attr"], "asdf"),
        (["root", "param1", "#text"], "val1"),
        (["root", "param2", "param3", "1234"], [None]),
        (["root", "param2", "param3", "4321"], 1.0),
    ]
    assert list(xml_envelope.get_subparams()) == expected_subparams

    # null
    null_envelope = BaseEnvelope.detect("null")
    assert isinstance(null_envelope, JSONEnvelope)
    assert null_envelope.unpacked_data() is None
    assert null_envelope.pack() == "null"
    expected_subparams = [([], None)]
    assert list(null_envelope.get_subparams()) == expected_subparams
    for subparam, value in expected_subparams:
        assert null_envelope.get_subparam(subparam) == value

    tiny_base64 = BaseEnvelope.detect("YWJi")
    assert isinstance(tiny_base64, TextEnvelope)
