from django import forms
from myapp.models import Query


class QueryForm(forms.ModelForm):
    class Meta:
        model = Query
        fields = ['timestamp', 'input']
