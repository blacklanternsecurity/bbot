# How it Works

## BBOT's Recursive Philosophy

The most important thing to understand about BBOT is that its philosophy is fundamentally different from other tools. At Black Lantern Security, we believe discovery is best done through ***Recursion***.

The vast majority of offensive tools are not recursive. Some may leverage recursion in a small isolated way, such as a dirbuster that finds subdirectories of subdirectories. What makes BBOT special is its 100+ custom modules, which have been carefully designed to work together in a ***truly recursive*** system. 

Each module ***consumes*** a certain type of data, uses it to discover something new, and ***produces*** another type, which it distributes to all the other modules. This happens again and again -- thousands of times during a scan -- spidering outwards in a recursive web of discovery.

The interactive graph below shows the relationships between modules and the data types they consume and produce.

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

BBOT inherits its recursive philosophy from [Spiderfoot](https://github.com/smicallef/spiderfoot). This enables its modules to work together in an efficient and very effective way.

For example, the `portscan` module consumes `DNS_NAME`, and produces `OPEN_TCP_PORT`. The `sslcert` module consumes `OPEN_TCP_PORT` and produces `DNS_NAME`. You can see how even these two modules, when enabled together, will feed each other recursively.

![module-recursion](https://github.com/blacklanternsecurity/bbot/assets/20261699/10ff5fb4-b3e7-453d-9772-7a26808b071e)

Every BBOT module is designed to interwork with all the others in this recursive system. Because of this, enabling even one module has the potential to increase your results exponentially. This is exactly how BBOT is able to outperform other tools.

## Event Flow

Below is a graph showing the internal event flow in BBOT. White lines represent queues. Notice how some modules run in sequence, while others run in parallel. With the exception of a few specific modules, most BBOT modules are parallelized.

![event-flow](https://github.com/blacklanternsecurity/bbot/assets/20261699/6cece76b-70bd-4690-a53f-02d42e6ed05b)
