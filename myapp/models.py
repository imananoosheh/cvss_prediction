from django.contrib.auth.models import User
from django.db import models
import datetime


# Create your models here.

class Query(models.Model):
    timestamp = models.DateField(default=datetime.datetime.now)
    output = models.TextField(blank=True)
    input = models.TextField()

    def __str__(self):
        return self.timestamp
