# How it Works

## BBOT's Recursive Philosophy

It's well-known that when you're doing recon, it's best to do it recursively. However, there are very few recursive tools, and the main reason for this is because making a recursive tool is hard. In particular, it's very difficult to build a large-scale recursive system that interacts with the internet, and to keep it stable. When we first set out to make BBOT, we didn't know this, and it was definitely a lesson we learned the hard way. BBOT's stability is thanks to its extensive [Unit Tests](./dev/tests.md).

BBOT inherits its recursive philosophy from [Spiderfoot](https://github.com/smicallef/spiderfoot), which means it is also ***event-driven***. Each of BBOT's 100+ modules ***consume*** a certain type of [Event](./scanning/events.md), use it to discover something new, and ***produce*** new events, which get distributed to all the other modules. This happens again and again -- thousands of times during a scan -- spidering outwards in a recursive web of discovery.

Below is an interactive graph showing the relationships between modules and the event types they produce and consume.

<!-- BBOT CHORD GRAPH -->
<div id="vis"></div>
<script type="text/javascript">
  window.addEventListener(
    'load',
    function() {
      vegaEmbed(
        '#vis',
        '../data/chord_graph/vega.json',
        {renderer: 'svg'}
      );
    }
  );
</script>
<!-- END BBOT CHORD GRAPH -->

## How BBOT Modules Work Together

Each BBOT module does one specific task, such as querying an API for subdomains, or running a tool like `nuclei`, and is carefully designed to work together with other modules inside BBOT's recursive system.

For example, the `portscan` module consumes `DNS_NAME`, and produces `OPEN_TCP_PORT`. The `sslcert` module consumes `OPEN_TCP_PORT` and produces `DNS_NAME`. You can see how even these two modules, when enabled together, will feed each other recursively.

![module-recursion](https://github.com/blacklanternsecurity/bbot/assets/20261699/10ff5fb4-b3e7-453d-9772-7a26808b071e)

Because of this, enabling even one module has the potential to increase your results exponentially. This is exactly how BBOT is able to outperform other tools.

To learn more about how events flow inside BBOT, see [BBOT Internal Architecture](./dev/architecture.md).
