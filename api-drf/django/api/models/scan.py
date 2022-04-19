import uuid
import logging
from django.db import models
from django.conf import settings
from django.dispatch import Signal
from channels.db import database_sync_to_async

from bbot.db.neo4j import Neo4j

log = logging.getLogger(__name__)

neo4j = Neo4j(uri=settings.NEO4J_URL, username=settings.NEO4J_USER, password=settings.NEO4J_PASS)


class ScanManager(models.Manager):
    def create(self, *args, **kwargs):
        res = self.model.objects.get_or_create(*args, **kwargs)
        return res[0]


class ScanTarget(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    campaign = models.ForeignKey("api.Campaign", on_delete=models.CASCADE)
    value = models.CharField(max_length=256)
    objects = ScanManager()

    class Meta:
        constraints = [models.UniqueConstraint(fields=["campaign_id", "value"], name="unique_target_per_campaign")]


class ScanModule(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    value = models.CharField(max_length=256)
    objects = ScanManager()


class Scan(models.Model):
    class ScanStatus(models.TextChoices):
        PENDING = "Pending"
        STARTING = "Starting"
        RUNNING = "Running"
        FINISHED = "Finished"
        FAILED = "Failed"
        CANCELED = "Canceled"

    class Event:
        __data = None

        def __init__(self, data):
            self.__data = data

        @property
        def id(self):
            return self.__data["id"].split(":")[0]

        @property
        def json(self):
            return self.__data

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    campaign = models.ForeignKey("api.Campaign", related_name="scans", on_delete=models.CASCADE)
    agent = models.ForeignKey("api.Agent", related_name="scans", on_delete=models.CASCADE)
    name = models.CharField(max_length=64)
    targets = models.ManyToManyField(ScanTarget, related_name="scans", blank=True)
    modules = models.ManyToManyField(ScanModule, related_name="scans", blank=True)
    status = models.CharField(max_length=10, choices=ScanStatus.choices, default=ScanStatus.PENDING)

    accepted = False

    @database_sync_to_async
    def get_target_list(self):
        return [t.value for t in self.targets.all()]

    @database_sync_to_async
    def get_module_list(self):
        return [m.value for m in self.modules.all()]

    def solicit_scan(sender, instance, created, **kwargs):
        if created:
            for session in instance.agent.sessions.all():
                session.ping(callback=instance.launch_scan)

    async def launch_scan(self, sender):
        if self.accepted == False:
            self.accepted = True
            scan_data = {
                "scan_id": str(self.id),
                "targets": await self.get_target_list(),
                "modules": await self.get_module_list(),
            }

            await sender.start_scan({"data": scan_data})
        else:
            log.debug("Scan already started; ignoring")

    def scan_event(sender, instance, event, *args, **kwargs):
        log.debug(event)
        neo4j.insert_events([sender.Event(event)])


scan_create = Signal()
scan_create.connect(Scan.solicit_scan, sender=Scan)

scan_event = Signal()
scan_event.connect(Scan.scan_event, sender=Scan)
