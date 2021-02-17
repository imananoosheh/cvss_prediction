from django.shortcuts import render, redirect

# Import necessary classes
from datetime import *
from .forms import QueryForm
from testing import testing_single_description


# Create your views here.

def single_decs_query(request):
    if request.method == 'POST':
        form = QueryForm(request.POST)
        if form.is_valid():
            input_description = form.cleaned_data['input']
            form.save(commit=False)
            output = testing_single_description(input_description)
            return render(request, 'myapp/single_decs_query.html',
                          {'output': output, 'input': input_description, 'form': form})
        else:
            return render(request, 'myapp/single_decs_query.html', {'form': form})
    else:
        form = QueryForm()
        return render(request, 'myapp/single_decs_query.html', {'form': form})

# def index(request):
#     if request.session.get('last_login'):
#         last_login = request.session['last_login']
#     else:
#         last_login = "Your last login was more than one hour ago"
#     top_list = Topic.objects.all().order_by('id')[:10]
#     return render(request, 'myapp/index.html', {'top_list': top_list, 'last_login': last_login})
