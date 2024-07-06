# How it Works

## BBOT's Recursive Philosophy

It is well-known that if you're doing recon, it's best to do it recursively. However, there are very few recursive tools out there, mainly because making a recursive tool (and keeping it stable) is pretty hard. Building a tool like BBOT would not have been possible without extensive [Unit Tests](./dev/tests.md). We are proud to have over 90% code coverage, and a full-fledged test for every module.

BBOT inherits its recursive philosophy from [Spiderfoot](https://github.com/smicallef/spiderfoot), which means it is also ***event-driven***. Each of BBOT's 100+ modules ***consumes*** a certain type of [Event](./scanning/events.md), uses it to discover something new, and ***produces*** new events, which it distributes to all the other modules. This happens again and again -- thousands of times during a scan -- spidering outwards in a recursive web of discovery.

Below is an interactive graph showing the relationships between modules and the event types they produce and consume.

<!-- BBOT CHORD GRAPH -->
<div id="vis"></div>
<script type="text/javascript">
  window.addEventListener(
    'load',
    function() {
      vegaEmbed(
        '#vis',
        '/bbot/data/chord_graph/vega.json',
        {renderer: 'svg'}
      );
    }
  );
</script>
<!-- END BBOT CHORD GRAPH -->

## How BBOT Modules Work Together

Each BBOT module does one specific task, like query an API for subdomains, or run a tool like `nuclei`. They are carefully designed to work together in an efficient and very effective way.

For example, the `portscan` module consumes `DNS_NAME`, and produces `OPEN_TCP_PORT`. The `sslcert` module consumes `OPEN_TCP_PORT` and produces `DNS_NAME`. You can see how even these two modules, when enabled together, will feed each other recursively.

![module-recursion](https://github.com/blacklanternsecurity/bbot/assets/20261699/10ff5fb4-b3e7-453d-9772-7a26808b071e)

Because of this, enabling even one module has the potential to increase your results exponentially. This is exactly how BBOT is able to outperform other tools.
