from django.db import models

# Create your models here.

class DeletedUser(models.Model): 
    username = models.CharField( max_length=25)
    email = models.EmailField( null=True)

    def __str__():
	      return "Del User"
