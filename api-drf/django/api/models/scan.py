import uuid
import logging
from django.db import models
from django.dispatch import Signal
from django.dispatch import receiver

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

    def launch_scan(sender, instance, created, **kwargs):
        if created:
            log.debug(f"Scan would be launched: {str(instance.id)}")


scan_create = Signal()
scan_create.connect(Scan.launch_scan, sender=Scan)
