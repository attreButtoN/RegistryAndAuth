from .models import *
from django_filters import rest_framework as filters


class TagsFilter(filters.FilterSet):

    class Meta:
        model = Article
        fields = [
            "tag"
        ]
