
from rest_framework import serializers
from  .models import *

class LoginSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    password = serializers.CharField(write_only=True)


class UserSerialiazer(serializers.ModelSerializer):
    class Meta:
        model=LoginUser
        fields=['user_id','password','is_verified']

class dataeditorserializer(serializers.ModelSerializer):
    class Meta:
        model=Student
        fields=['user_id','first_name','last_name','admission_date','email','aadhar','phone_number','role','Branch','Year','semester','section','password','religion','dob']        

    
class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.IntegerField()
    email = serializers.EmailField()

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()    


class PasswordtakingSerializer(serializers.Serializer):
    password=serializers.CharField(write_only=True)
    confirm_password=serializers.CharField(write_only=True)

class subjecteditorserializer(serializers.ModelSerializer):
    class Meta:
        model=Subjects
        fields=['name','code','semester']


class attendenceeditorserializer(serializers.ModelSerializer):
    class Meta:
        model=Attendance
        fields=['date','student_id','subject','is_present']

class facultyeditorserializer(serializers.ModelSerializer):
    class Meta:
        model=Faculty
        fields=['user_id','first_name','last_name','email','phone_number','role','Post','Department','password','aadhar','address','gender','profile_photo_url']   

class classassignserializer(serializers.ModelSerializer):
    class Meta:
        model=classassigned
        fields=['subject_code','faculty','semester','class_assigned']        

class exameditorserializer(serializers.ModelSerializer):
    class Meta:
        model=exam
        fields=['exam_name','total_marks','date','duration','session']


class ExamDataAdmitResultserializer(serializers.ModelSerializer):
    class Meta:
        model=ExamDataAdmitResult
        fields=['user_id','exam_name','session','result','admit_card','date']
        
        
#serializer for giving exam data     

class givingexamdataserializer(serializers.ModelSerializer):
    class Meta:
        model = exam
        fields = '__all__'   
        
class givingexamadmitresultdataserializer(serializers.ModelSerializer):
    class Meta:
        model = ExamDataAdmitResult
        fields = ['user_id','exam_name','session','result','admit_card','date']  
        
        
class eventdataserializer(serializers.ModelSerializer):
    class Meta:
        model = eventsdata
        fields = '__all__'        
        
        
class ImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadedImage
        fields = ['image_url']   
        
        
class timetableserializer(serializers.ModelSerializer):
    class Meta:
        model = timetabledata
        fields = '__all__'             
        
     
     
# Serializers for feedback form
class feedbackserializer(serializers.ModelSerializer):
    class Meta:
        model = feedbacktable
        fields = '__all__'