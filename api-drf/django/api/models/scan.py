import uuid
import logging
from django.db import models
from django.dispatch import Signal
from channels.db import database_sync_to_async

log = logging.getLogger(__name__)

# log.debug(bbot.modules.get_modules())


class ScanTarget(models.Model):
    #   class ScanTargetType(models.TextChoices):
    #       DOMAIN = "0", "Domain"
    #       IP = "1", "IP"
    #       SUBNET = "2", "Subnet"
    #       URL = "3", "URL"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey("api.Scan", related_name="targets", on_delete=models.CASCADE)
    value = models.CharField(max_length=256)


class ScanModule(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey("api.Scan", related_name="modules", on_delete=models.CASCADE)
    value = models.CharField(max_length=256)


class Scan(models.Model):
    class ScanStatus(models.TextChoices):
        PENDING = "0", "Pending"
        RUNNING = "1", "Running"
        COMPLETED = "2", "Completed"
        FAILED = "3", "Failed"
        CANCELED = "4", "Canceled"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    campaign = models.ForeignKey("api.Campaign", related_name="scans", on_delete=models.CASCADE)
    agent = models.ForeignKey("api.Agent", related_name="scans", on_delete=models.CASCADE)
    name = models.CharField(max_length=64)
    status = models.CharField(max_length=1, choices=ScanStatus.choices, default=ScanStatus.PENDING)

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


scan_create = Signal()
scan_create.connect(Scan.solicit_scan, sender=Scan)
