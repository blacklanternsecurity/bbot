# Custom Yara Rules

### Overview
Through the `excavate` internal module, BBOT supports searching through HTTP response data using custom YARA rules.

This feature can be utilized with the command line option `--custom-yara-rules` or `-cy`, followed by a file containing the YARA rules.

Example:

```
bbot -m httpx --custom-yara-rules=test.yara -t http://example.com/
```

Where `test.yara` is a file on the filesystem. The file can contain multiple YARA rules, separated by lines.

YARA rules can be quite simple, the simplest example being a single string search:

```
rule find_string {
    strings:
        $str1 = "AAAABBBB"

    condition:
        $str1
}
```

To look for multiple strings, and match if any of them were to hit:

```
rule find_string {
    strings:
        $str1 = "AAAABBBB"
        $str2 = "CCCCDDDD"

    condition:
        any of them
}
```

One of the most important capabilities is the use of regexes within the rule, as shown in the following example.

```
rule find_AAAABBBB_regex {
    strings:
        $regex = /A{1,4}B{1,4}/

    condition:
        $regex
}

```

*Note: YARA uses it's own regex engine that is not a 1:1 match with python regexes. This means many existing regexes will have to be modified before they will work with YARA. The good news is: YARA's regex engine is FAST, immensely more fast than pythons!*

Further discussion of art of writing complex YARA rules goes far beyond the scope of this documentation. A good place to start learning more is the [official YARA documentation](https://yara.readthedocs.io/en/stable/writingrules.html).

The YARA engine provides plenty of room to make highly complex signatures possible, with various conditional operators available. Multiple signatures can be linked together to create sophisticated detection rules that can identify a wide range of specific content. This flexibility allows the crafting of efficient rules for detecting security vulnerabilities, leveraging logical operators, regular expressions, and other powerful features. Additionally, YARA's modular structure supports easy updates and maintenance of signature sets.

### Custom options

BBOT supports the use of a few custom `meta` attributes within YARA rules, which will alter the behavior of the rule and the post-processing of the results.

#### description

The description of the rule. Will end up in the description of any produced events if defined.

Example with no description provided:

```
[FINDING] {"description": "Custom Yara Rule [find_string] Matched via identifier [str1]", "host": "example.com", "url": "http://example.com"} excavate
```

Example with the description added:

```
[FINDING] {"description": "Custom Yara Rule [AAAABBBB] with description: [contains our test string] Matched via identifier [str1]", "host": "example.com, "url": "http://example.com"}     excavate
```

That FINDING was produced with the following signature:

```
rule AAAABBBB {

    meta:
        description = "contains our test string"
    strings:
        $str1 = "AAAABBBB"
    condition:
        $str1
}
```

#### tags

Tags specified with this option will be passed-on to any resulting emitted events. Tags are provided as a comma separated string, as shown below:

Lets expand on the previous example:

```
rule AAAABBBB {

    meta:
        description = "contains our test string"
        tags = "tag1,tag2,tag3"
    strings:
        $str1 = "AAAABBBB"
    condition:
        $str1
}
```

Now, the BBOT FINDING includes these custom tags, as with the following output:

```
[FINDING] {"description": "Custom Yara Rule [AAAABBBB] with description: [contains our test string] Matched via identifier [str1]", "host": "example.com", "url": "http://example.com/"} excavate   (tag1, tag2, tag3)
```

#### emit_match

When set to True, the contents returned from a successful extraction via a YARA regex will be included in the FINDING event which is emitted.

Consider the following example YARA rule:

```
rule SubstackLink
{
    meta:
        description = "contains a Substack link"
        emit_match = true
    strings:
        $substack_link = /https?:\/\/[a-zA-Z0-9.-]+\.substack\.com/
    condition:
        $substack_link
}
```

When run against the Black Lantern Security homepage with the following BBOT command:

```
bbot -m httpx --custom-yara-rules=substack.yara -t http://www.blacklanternsecurity.com/

```

We get the following result. Note that the finding now contains the actual link that was identified with the regex.

```
[FINDING] {"description": "Custom Yara Rule [SubstackLink] with description: [contains a Substack link] Matched via identifier [substack_link] and extracted [https://blacklanternsecurity.substack.com]", "host": "www.blacklanternsecurity.com", "url": "https://www.blacklanternsecurity.com/"}    excavate
```
