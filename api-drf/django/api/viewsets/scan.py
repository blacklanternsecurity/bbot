import logging
from django.db import transaction
from rest_framework import viewsets, status
from rest_framework.response import Response

from api.serializers.scan import *

log = logging.getLogger(__name__)


class ScanTargetViewSet(viewsets.ModelViewSet):
    serializer_class = ScanTargetSerializer
    queryset = ScanTargetSerializer.Meta.model.objects.all()


class ScanViewSet(viewsets.ModelViewSet):
    serializer_class = ScanSerializer
    queryset = ScanSerializer.Meta.model.objects.all()

    def create(self, request, *args, **kwargs):
        raw_targets = request.data.pop("targets")
        raw_modules = request.data.pop("modules")
        request.data["targets"] = []
        request.data["modules"] = []

        instance = None
        serializer = self.get_serializer(data=request.data)
#       serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            targets = []
            for target in raw_targets:
                targets.append({
                    "campaign": serializer.initial_data["campaign"],
                    "value": target
                })
            t_serializer = ScanTargetSerializer(data=targets, many=True)
            t_serializer.is_valid(raise_exception=True)
            self.perform_create(t_serializer)

            modules = []
            for module in raw_modules:
                modules.append({"value": module})
            m_serializer = ScanModuleSerializer(data=modules, many=True)
            m_serializer.is_valid(raise_exception=True)
            self.perform_create(m_serializer)

            serializer.initial_data["targets"] = [ t["id"] for t in t_serializer.data ]
            serializer.initial_data["modules"] = [ m["id"] for m in m_serializer.data ]

            serializer.is_valid(raise_exception=True)
            instance = serializer.save()

        if instance is not None:
            scan_create.send(
                sender=self.serializer_class.Meta.model, instance=instance, created=True
            )

        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )
