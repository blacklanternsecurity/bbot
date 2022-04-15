import uuid
import logging
from django.db import models

log = logging.getLogger(__name__)


class Campaign(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=32, unique=True)
