# Custom Yara Rules

### Overview 
Though the `excavate` interanal module, BBOT supports searching through HTTP response data using custom YARA rules. 

This feature can be utilized with the command line option `--custom-yara-rules` or `-cy`, followed by a file containing the YARA rules.


### Custom options

BBOT supports the use of a few custom `meta` attributes within YARA rules, which will alter the behavior of the rule and the post-processing of the results.

#### description

The description of the rule. Will end up in the description of any produced events if defined.

#### tags

Tags specified with this option will be passed-on to any resulting emitted events. Provided as a comma separated string, as shown below:

TBA

#### emit_match

When set to True, the contents returned from a successful extraction via a YARA regex will be included in the FINDING event which is emitted.

Consider the following example:

TBA

### YARA Resources

TBA