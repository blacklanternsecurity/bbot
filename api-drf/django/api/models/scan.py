import json
import uuid
import logging
from django.db import models

log = logging.getLogger(__name__)


class Scan(models.Model):
    class ScanStatus(models.TextChoices):
        PENDING = "0", "Pending"
        RUNNING = "1", "Running"
        COMPLETED = "2", "Completed"
        FAILED = "3", "Failed"
        CANCELED = "4", "Canceled"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    campaign = models.ForeignKey("api.Campaign", related_name="scans", on_delete=models.CASCADE)
    name = models.CharField(max_length=64)
    status = models.CharField(max_length=1, choices=ScanStatus.choices, default=ScanStatus.PENDING)
