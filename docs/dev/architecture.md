# BBOT Internal Architecture

Here is a basic overview of BBOT's internal architecture.

## Queues

Being both ***recursive*** and ***event-driven***, BBOT makes heavy use of queues. These enable smooth communication between the modules, and ensure that large numbers of events can be produced without slowing down or clogging up the scan.

Every module in BBOT has both an ***incoming*** and ***outgoing*** queue. Event types matching the module's `WATCHED_EVENTS` (e.g. `DNS_NAME`) are queued in its incoming queue, and processed by the module's `handle_event()` (or `handle_batch()` in the case of batched modules). If the module finds anything interesting, it creates an event and places it in its outgoing queue, to be processed by the scan and redistributed to other modules.

## Event Flow

Below is a graph showing the internal event flow in BBOT. White lines represent queues. Notice how some modules run in sequence, while others run in parallel. With the exception of a few specific modules, most BBOT modules are parallelized.

![event-flow](https://github.com/blacklanternsecurity/bbot/assets/20261699/6cece76b-70bd-4690-a53f-02d42e6ed05b)

For a higher-level overview, see [How it Works](../how_it_works.md).
