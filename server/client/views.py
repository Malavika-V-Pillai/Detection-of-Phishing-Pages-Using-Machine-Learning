from django.shortcuts import render
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from ml.views import pred,extract
# Create your views here.
print("Machine Learning Model Object Creating...")
obj = pred()
print("Machine Learning Model Object Created")
def api(request,id):
    val = URLValidator()
    try:
        val(id)
        features = extract(id)
        Result = obj.prediction([features])
        if Result == 1:
            output = "Phishing Page"
        else:
            output = "Legitimate Page"
        return JsonResponse({'status':'Success','output':output})
    except ValidationError:
        return JsonResponse({'status':'failed','output':'not a valid url'})
    except:
        return JsonResponse({'status':'failed','output':'Server is not reachable'})
def result(request):
    print(request)
    if(request.method=="GET"):
        return render(request,'home.html')
    else:
        url=request.POST.get('url')
        print("Url is "+url)
        features = extract(url)
        Result = obj.prediction([features])
        print(type(Result))
        if Result == 1:
            output = "Phishing Page"
        else:
            output = "Legitimate Page"
        return render(request,'home.html',{'url':output})