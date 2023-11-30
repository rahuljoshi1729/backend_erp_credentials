""" @api_view(['POST'])
def custom_logout(request):
    auth_logout(request)
    return JsonResponse({'message': 'Logout successful'}) """

from django.http import JsonResponse
from django.http import HttpResponse
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import *
from .models import *
from .emails import send_otp_via_email,generate_jwt_token,send_passwordreset_mail,decode_jwt_token_reset,decode_jwt_token
import jwt
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def get_jwt_token_from_cookies(request):
    jwt_token = request.COOKIES.get('jwt_token')
    if jwt_token:
        try:
            # Decode and verify the JWT token
            user_id, role = decode_jwt_token(jwt_token)
            return user_id, role
        except jwt.ExpiredSignatureError:
            # Handle token expiration
            return JsonResponse({'error': 'Token expired'}, status=401)
        except jwt.InvalidTokenError:
            # Handle invalid token
            return JsonResponse({'error': 'Invalid token'}, status=401)
    return None


class studentdataeditor(APIView):
    @csrf_exempt  
    def post(self, request):
        jwt_token = request.COOKIES.get('jwt_token')
        print(jwt_token)
        
        if jwt_token:
            try:
                user_id, role = decode_jwt_token(jwt_token)
                # print(user_id, role)
                
                if role == 'student':
                    data = request.data
                    serializers = dataeditorserializer(data=data)

                    if serializers.is_valid():
                        serializers.save()
                        return Response({
                            'status': 201,
                            'message': 'Data created',
                            'data': serializers.data,
                        })

                    return Response({
                        'status': 400,
                        'message': 'Something went wrong',
                        'data': serializers.errors,
                    })
                else:
                    return JsonResponse({"message": "Access not allowed",'status':404})

            except jwt.ExpiredSignatureError:
                return JsonResponse({'error': 'Token expired','status':401})  # Handle token expiration

        else:
            return JsonResponse({'error': 'Invalid token','status':401})  # Handle invalid token check for above error            
         

#API to take faculty data
class facultyeditor(APIView):
    @csrf_exempt  
    def post(self, request):
        jwt_token = request.COOKIES.get('jwt_token')
        print(jwt_token) 
        
        if jwt_token:
            try:
                user_id, role = decode_jwt_token(jwt_token)
                # print(user_id, role)
                
                if role == 'student':
                    data = request.data
                    serializers = facultyeditorserializer(data=data)

                    if serializers.is_valid():
                        serializers.save()
                        return Response({
                            'status': 201,
                            'message': 'Data created',
                            'data': serializers.data,
                        })

                    return Response({
                        'status': 400,
                        'message': 'Something went wrong',
                        'data': serializers.errors,
                    })
                else:
                    return JsonResponse({"message": "Access not allowed",'status':404})

            except jwt.ExpiredSignatureError:
                return Response({'error': 'Token expired','status':401})  # Handle token expiration

        else:
            return Response({'error': 'Invalid token','status':401})  # Handle invalid token check for above error      

#API to add subject
class subjecteditor(APIView):
    @csrf_exempt  
    def post(self, request):
        jwt_token = request.COOKIES.get('jwt_token')
        print(jwt_token)
        
        if jwt_token:
            try:
                user_id, role = decode_jwt_token(jwt_token)
                # print(user_id, role)
                
                if role == 'student':
                    data = request.data
                    serializers = subjecteditorserializer(data=data)

                    if serializers.is_valid():
                        serializers.save()
                        return Response({
                            'status': 201,
                            'message': 'Data created',
                            'data': serializers.data,
                        })

                    return Response({
                        'status': 400,
                        'message': 'Something went wrong',
                        'data': serializers.errors,
                    })
                else:
                    return JsonResponse({"message": "Access not allowed",'status':404}, status=404)

            except jwt.ExpiredSignatureError:
                return Response({'error': 'Token expired','status':401}, status=401)  # Handle token expiration

        else:
            return Response({'error': 'Invalid token','status':401}, status=401)  # Handle invalid token check for above error 


class attendanceeditor(APIView):
    @csrf_exempt  
    def post(self, request):
        jwt_token = request.COOKIES.get('jwt_token')
        print(jwt_token)
        
        if jwt_token:
            try:
                user_id, role = decode_jwt_token(jwt_token)
                # print(user_id, role)
                
                if role == 'student':
                    data = request.data
                    serializers = attendenceeditorserializer(data=data)

                    if serializers.is_valid():
                        serializers.save()
                        return Response({
                            'status': 201,
                            'message': 'Data created',
                            'data': serializers.data,
                        })

                    return Response({
                        'status': 400,
                        'message': 'Something went wrong',
                        'data': serializers.errors,
                    })
                else:
                    return JsonResponse({"message": "Access not allowed","status":404}, status=404)

            except jwt.ExpiredSignatureError:
                return Response({'error': 'Token expired',"status":401}, status=401)  # Handle token expiration

        else:
            return Response({'error': 'Invalid token',"status":401}, status=401)  # Handle invalid token check for above error 
        
        

class classassignview(APIView):
    @csrf_exempt  
    def post(self, request):
        jwt_token = request.COOKIES.get('jwt_token')
        print(jwt_token)
        
        if jwt_token:
            try:
                user_id, role = decode_jwt_token(jwt_token)
                # print(user_id, role)
                
                if role == 'student':
                    data = request.data
                    serializers = classassignserializer(data=data)

                    if serializers.is_valid():
                        serializers.save()
                        return Response({
                            'status': 201,
                            'message': 'Data created',
                            'data': serializers.data,
                        })

                    return Response({
                        'status': 400,
                        'message': 'Something went wrong',
                        'data': serializers.errors,
                    })
                else:
                    return JsonResponse({"message": "Access not allowed",'status':404}, status=404)

            except jwt.ExpiredSignatureError:
                return Response({'error': 'Token expired','status':401}, status=401)  # Handle token expiration

        else:
            return Response({'error': 'Invalid token','status':401}, status=401)  # Handle invalid token check for above error
        
        
#API FOR ADDING  EXAMS DATA 
class examdataeditiorview(APIView):
    @csrf_exempt  
    def post(self, request):
        jwt_token = request.COOKIES.get('jwt_token')
        print(jwt_token)
        
        if jwt_token:
            try:
                user_id, role = decode_jwt_token(jwt_token)
                # print(user_id, role)
                
                if role == 'student':
                    data = request.data
                    serializers = exameditorserializer(data=data)

                    if serializers.is_valid():
                        serializers.save()
                        return Response({
                            'status': 201,
                            'message': 'Data created',
                            'data': serializers.data,
                        })

                    return Response({
                        'status': 400,
                        'message': 'Something went wrong',
                        'data': serializers.errors,
                    })
                else:
                    return JsonResponse({"message": "Access not allowed",'status':404,'status':401}, status=404)

            except jwt.ExpiredSignatureError:
                return Response({'error': 'Token expired','status':401}, status=401)  # Handle token expiration

        else:
            return Response({'error': 'Invalid token','status':401}, status=401)  # Handle invalid token check for above error
        
#API FOR ADDING  EXAMS DATA ADMIT CARD AND RESULT FOR A PARTICULAR USER
class examdataadmitresulteditiorview(APIView):
    @csrf_exempt  
    def post(self, request):
        jwt_token = request.COOKIES.get('jwt_token')
        print(jwt_token)
        
        if jwt_token:
            try:
                user_id, role = decode_jwt_token(jwt_token)
                # print(user_id, role)
                
                if role == 'student':
                    data = request.data
                    serializers = ExamDataAdmitResultserializer(data=data)

                    if serializers.is_valid():
                        serializers.save()
                        return Response({
                            'status': 201,
                            'message': 'Data created',
                            'data': serializers.data,
                        })

                    return Response({
                        'status': 400,
                        'message': 'Something went wrong',
                        'data': serializers.errors,
                    })
                else:
                    return JsonResponse({"message": "Access not allowed",'status':404}, status=404)

            except jwt.ExpiredSignatureError:
                return Response({'error': 'Token expired','status':401}, status=401)  # Handle token expiration

        else:
            return Response({'error': 'Invalid token','status':401}, status=401)  # Handle invalid token check for above error        
        
        
             
#API FOR LOGIN OF USER       
class login(APIView):
    def post(self,request):
        try:
            data=request.data
            serializers=UserSerialiazer(data=data)
            if serializers.is_valid():
                user_id = serializers.validated_data['user_id']
                password = serializers.validated_data['password']
                
                print(user_id,password)
                #Check if user_id is in Student model
                student = Student.objects.filter(user_id=user_id).first()
                # If not found in Student model, check in Teacher model
                if not student:
                    faculty = Faculty.objects.filter(user_id=user_id).first()
                    if not faculty:
                        return JsonResponse({'error': 'Invalid credentials','status':404}, status=404)
                    user = faculty
                else:
                    user = student

                if user.password == password:
                    email=user.email
                    send_otp_via_email(email,user_id,password)
                    return JsonResponse({'message': 'OTP sent to email','status':201},status=201)

                else:
                    return JsonResponse({'error': 'Invalid credentials','status':401}, status=401)    
    

            return JsonResponse({
                'status':400,
                'message':'something went wrong',
                'data':serializers.errors,
            })   
        
        except Exception as e:
            print(e)
            return JsonResponse({'error': 'Internal server error','status':500}, status=500)



from django.http import HttpResponse
from django.middleware.csrf import rotate_token

class VerifyOTP(APIView):
    def post(self,request):
        try:
            data=request.data
            serializers=VerifyOTPSerializer(data=data)
            if serializers.is_valid():
                otp=serializers.validated_data['otp']
                user_id=serializers.validated_data['user_id']
                #checking in loginuser model
                user=LoginUser.objects.filter(otp=otp).first()
                
                if user:
                    
                    #fetching user_id form student/Faculty model
                    student = Student.objects.filter(user_id=user_id).first()
                    if not student:
                        faculty = Faculty.objects.filter(user_id=user_id).first()
                        if not faculty:
                            return JsonResponse({'error': 'invalid','status':404})
                        user_ = faculty
                    else:
                        user_ = student
                    user_id=user_.user_id    
                    role=user_.role
                    token=generate_jwt_token(user_id=user_id, role=role)
                    user.is_verified=True
                    user.save()
                    user.delete()

                    #cokkie setting
                    response = JsonResponse({'user_id': user_id, 'otp_sent': True, 'token': token,'role':role,'status':201})
                    response.set_cookie('jwt_token', token, httponly=True, secure=True)  # Use secure=True in production with HTTPS
                    return response
                else:
                    return JsonResponse({'error': 'Invalid OTP','status':401}, status=401)
            return JsonResponse({
                'status':400,
                'message':'something went wrong',
                'data':serializers.errors,
            })    

        except Exception as e:
            print(e)    
            return JsonResponse({'error': 'Internal server error','status':500}, status=500)

#Api which will be called when user will click on forgot password. sending mail to user having password reset link
class PasswordResetRequest(APIView):
    def post(self, request):
        try:
            data = request.data
            serializers = PasswordResetSerializer(data=data)

            if serializers.is_valid():
                email = serializers.validated_data.get('email')

                student_user = Student.objects.filter(email=email).first()
                faculty_user = Faculty.objects.filter(email=email).first()

                if not student_user :
                    if not faculty_user:
                        return JsonResponse({'error': 'Unauthrized email','status':404}, status=404)
                    user = 'faculty'
                user='student'
                # Assuming you have a function to send password reset mail
                print(email)
                token=send_passwordreset_mail(email)

                return JsonResponse({'message': 'Password reset link sent to email',
                                     'token':token,'role':user,'status':201},status=201)

            return JsonResponse({'error': 'Invalid data','status':400}, status=400)

        except Exception as e:
            print(e)
            # Handle other exceptions as needed
            return JsonResponse({'error': 'Internal Server Error','status':500}, status=500)    


#taking new password from user and updating it in database.

#used global dictionary to store that token has been used
used_tokens = {}
#token is sent in url and new password is taken from user        
class PasswordReset(APIView):
            def patch(self, request):
                token=request.headers.get('token')
                print(request.data)
                token = request.data.get('token')
                print(token)
                if token is None:
                    return JsonResponse({'error': 'token is required','status':400}, status=400)      # Handle the case where 'email' is not provided
                
                # Check if the token has already been used
                if used_tokens.get(token):
                    return JsonResponse({'error': 'Token has already been used','status':400}, status=400)
                
                email=decode_jwt_token_reset(token)
                print(email)
            
                if email is None:
                    return JsonResponse({'error': 'Invalid token','status':401}, status=401)
                student=Student.objects.filter(email=email).first()
                if student is None:
                    faculty=Faculty.objects.filter(email=email).first()
                    if faculty is None:
                        return JsonResponse({'error': 'User not found','status':404}, status=404)
                    user=faculty
                else:
                    user=student
                
                serializers = PasswordtakingSerializer(data=request.data)
                if serializers.is_valid():
                    password= serializers.validated_data.get('password')
                    confirm_password= serializers.validated_data.get('confirm_password')

                    if password != confirm_password:
                        return JsonResponse({'error': 'Passwords do not match','status':400}, status=400)
                    user.password=password
                    user.save()
                    #once token used setting it true
                    used_tokens[token] = True
                    
                    return JsonResponse({'message': 'Password reset successful','status':201})
                else:
                    return JsonResponse(serializers.errors,status=400)    
                

#API when click on attendace button          
from django.views.decorators.csrf import csrf_exempt
import jwt
from rest_framework.decorators import api_view

"""@api_view(['POST'])
@csrf_exempt
def Attendanceview(request):
    print(request.headers)
    jwt_token = request.COOKIES.get('jwt_token')
    print(jwt_token)
    if jwt_token:
            try:
        
                user_id, role = decode_jwt_token(jwt_token)
                print(user_id, role)
                #getting data of student
                Studentuser=Student.objects.get(user_id=user_id)
                semester=Studentuser.semester
                section=Studentuser.section
                name=Studentuser.first_name+" "+Studentuser.last_name
                #getting data of student
                subjectuser=Subjects.objects.filter(semester=semester)
                subjectuserlist=list(subjectuser)
                subcodedic={}
                for a in subjectuserlist:
                    subcodedic[a.code]=a.name
                print(subcodedic)
                #now getting the faculty who is taking that subject
                subfaculdic={}
                for key in subcodedic:
                    classassigneduser=classassigned.objects.get(subject_code=key,class_assigned=section,semester=semester)
                    facultyuser=Faculty.objects.get(user_id=classassigneduser.faculty)
                    if classassigneduser:
                        faculty=classassigneduser.faculty
                        subfaculdic[key]=facultyuser.first_name+" "+facultyuser.last_name
                    else:
                        subfaculdic[key]="Not Assigned"    
                print(subfaculdic) 
                data = {}
                total_classes=0
                present=0
                for key in subcodedic:
                    temp=[]
                    #print(key)
                    attendance_user = Attendance.objects.filter(student_id=user_id, subject=key)
                    faculty_name = subfaculdic[key]
                    temp.append(subcodedic[key])
                    temp.append(faculty_name)
                   # print(data)
                    attendance_user_list = list(attendance_user)
                    #print(attendance_user_list)
                    temps=[]
                   
                    for a in attendance_user_list:
                        tempi=[]
                        #print(a)
                        date_value = str(a.date)
                        is_present_value = a.is_present
                        tempi.append(date_value)
                        tempi.append(is_present_value)
                        total_classes+=1
                        if is_present_value==1:
                            present+=1
                       # print(date_value, is_present_value)
                       # print(total_classes,present)
                        temps.append(tempi)
                    data[str(tuple(temp))]=temps
                print(data)   



                #getting toatal attendace and absent    
            
                return JsonResponse({"message":"success",
                                 "name":name,
                                 "semester":semester,
                                 "section":section,
                                "user_id":user_id,
                                "role":role,
                                "total_classes":total_classes,
                                "present":present,
                                "absent":total_classes-present,
                                "data":data,
                                "status":201},status=201) 
                
            except jwt.ExpiredSignatureError:  
                return JsonResponse({'error': 'Token expired','status':401}, status=401)
    else:
            return JsonResponse({'error': 'Invalid token','status':401}, status=401)  """
            
            
            
@api_view(['POST'])
@csrf_exempt
def Attendanceview(request):
    print(request.headers)
    a=request.headers
    #print(request.META)
    #print(request.headers.get('Authorization'))
    jwt_token = request.headers.get('token')
    jwt_token = a.get('headers', {}).get('token','')
    print(request.data)
    print(jwt_token)

    #jwt_token = request.data.get('data', {}).get('token')
    
    
    
    #jwt_token = request.headers.get('token')
    #jwt_token = request.COOKIES.get('jwt_token')
    if jwt_token:
            try:
        
                user_id, role = decode_jwt_token(jwt_token)
                print(user_id, role)
                #getting data of student
                Studentuser=Student.objects.get(user_id=user_id)
                semester=Studentuser.semester
                section=Studentuser.section
                name=Studentuser.first_name+" "+Studentuser.last_name
                profile_url=Studentuser.profile_photo_url
                #getting data of student
                subjectuser=Subjects.objects.filter(semester=semester)
                subjectuserlist=list(subjectuser)
                subcodedic={}
                for a in subjectuserlist:
                    subcodedic[a.code]=a.name
                print(subcodedic)
                print(semester,section)
                #now getting the faculty who is taking that subject
                subfaculdic={}
                for key in subcodedic:
                    print(key)
                    classassigneduser=classassigned.objects.get(subject_code=key,class_assigned=section,semester=semester)
                    facultyuser=Faculty.objects.get(user_id=classassigneduser.faculty)
                    print(facultyuser)
                    if classassigneduser:
                        faculty=classassigneduser.faculty
                        subfaculdic[key]=facultyuser.first_name+" "+facultyuser.last_name
                    else:
                        subfaculdic[key]="Not Assigned"    
                print(subfaculdic) 
                data = {}
                total_classes=0
                present=0
                for key in subcodedic:
                    temp=[]
                    #print(key)
                    attendance_user = Attendance.objects.filter(student_id=user_id, subject=key)
                    faculty_name = subfaculdic[key]
                    temp.append(subcodedic[key])
                    temp.append(faculty_name)
                   # print(data)
                    attendance_user_list = list(attendance_user)
                    #print(attendance_user_list)
                    temps=[]
                   
                    for a in attendance_user_list:
                        tempi=[]
                        #print(a)
                        date_value = str(a.date)
                        is_present_value = a.is_present
                        tempi.append(date_value)
                        tempi.append(is_present_value)
                        total_classes+=1
                        if is_present_value==1:
                            present+=1
                       # print(date_value, is_present_value)
                       # print(total_classes,present)
                        temps.append(tempi)
                    data[str(tuple(temp))]=temps
                print(data)   



                #getting toatal attendace and absent    
            
                return JsonResponse({"message":"success",
                                 "name":name,
                                 "semester":semester,
                                 "section":section,
                                "user_id":user_id,
                                "role":role,
                                "profile_url":profile_url,
                                "total_classes":total_classes,
                                "present":present,
                                "absent":total_classes-present,
                                "data":data,
                                "status":201},status=201) 
                
            except jwt.ExpiredSignatureError:  
                return JsonResponse({'error': 'Token expired','status':401}, status=401)
    else:
            return JsonResponse({'error': 'Invalid token','status':401}, status=401)      


#API to get data of exam related to a particular user
@api_view(['GET'])
def get_examdata(request):
    jwt_token = request.data.get('data', {}).get('token')
   # jwt_token = request.COOKIES.get('jwt_token')
    if jwt_token:
        user_id, role = decode_jwt_token(jwt_token)
        if user_id is None:
            return Response({'error': 'Invalid token','status':401}, status=401)
        exam_data = exam.objects.all()
        serializer = givingexamdataserializer(exam_data, many=True)
        extracted_data = []
        for data in serializer.data:
            date=data['date']
            print(date)
            exam_result_admit_data = ExamDataAdmitResult.objects.filter(date=date,user_id=user_id)
            if exam_result_admit_data.exists():
                serializer1 = givingexamadmitresultdataserializer(exam_result_admit_data, many=True)
                extracted_data.append(serializer1.data)
            print(serializer1.data)
        return Response({"exam_data":serializer.data,
                    "admit_card_result_data":extracted_data,
                    "status":201},status=201)
    
    else:
        return Response({'error': 'token not found','status':403}, status=403)
    
    
    
class eventpostview(APIView):
    def post(self,request):
        jwt_token=request.data.get('data', {}).get('token')
        jwt_token = request.COOKIES.get('jwt_token')    
        if jwt_token:
            user_id, role = decode_jwt_token(jwt_token)
            if user_id is None:
                return Response({'error': 'Invalid token','status':401}, status=401)
            if role=='student':
                data=request.data
                serializers=eventdataserializer(data=data)
                if serializers.is_valid():
                    serializers.save()
                    return Response({
                        'status': 201,
                        'message': 'Data created',
                        'data': serializers.data,
                    })
                else:
                    return Response({
                        'status': 400,
                        'message': 'input data',
                        'data': serializers.errors,
                    })     
            else:
                return Response({'error': 'Access not allowed','status':405}, status=405)        
        else:
            return Response({'error': 'token not found','status':403}, status=403)    
    
    
class geteventdataview(APIView):
    def get(self,request):
        event_data=eventsdata.objects.all()
        serializers=eventdataserializer(event_data,many=True)
        if not serializers.data:
            return Response({'error': 'No data found','status':204}, status=204)
        return Response({"event_data":serializers.data,"status":201},status=201)
    
import cloudinary.uploader 
from rest_framework import status
#Example api for how storing data in cloudinary works
""" class ImageUploadView(APIView):
    def post(self, request, *args, **kwargs):
        image = request.data.get('image')

        # Upload the image to Cloudinary
        result = cloudinary.uploader.upload(image)

        # Save the Cloudinary URL to the database
        uploaded_image = UploadedImage.objects.create(image_url=result['secure_url'])

        serializer = ImageSerializer(uploaded_image)

        return Response(serializer.data, status=status.HTTP_201_CREATED)  """
    
    
#uploading timetable    
class timetableuploader(APIView):
    def post(self,request):
        jwt_token=request.data.get('data', {}).get('token')
        jwt_token = request.COOKIES.get('jwt_token')    
        if jwt_token:
            user_id, role = decode_jwt_token(jwt_token)
            if user_id is None:
                return Response({'error': 'Invalid token','status':401}, status=401)
            if role=='faculty':
                serializers=timetableserializer(data=request.data)
                if serializers.is_valid():
                    image_data = request.data.get('image')
                    cloudinary_response = cloudinary.uploader.upload(image_data)
                    serializers.validated_data['time_table_url'] = cloudinary_response['url']
                    serializers.save()
                    return Response({
                        'status': 201,
                        'message': 'Data created',
                        'data': serializers.data,
                    })
                else:
                    return Response({
                        'status': 400,
                        'message': 'input data',
                        'data': serializers.errors,
                    })
            else:
                return Response({'error': 'no access','status':403}, status=403)    
                
class gettimetable(APIView):
    def get(self,request):
        timetable_data=timetabledata.objects.all()
        serializers=timetableserializer(timetable_data,many=True)
        if not serializers.data:
            return Response({'error': 'No data found','status':204}, status=204)
        return Response({"timetable_data":serializers.data,"status":201},status=201)   
               
               
class changepassword(APIView):
    def patch(self,request):
        #jwt_token=request.data.get('data', {}).get('token')
        jwt_token = request.data.get('token')
       # jwt_token = request.COOKIES.get('jwt_token')    
        if jwt_token:
            user_id, role = decode_jwt_token(jwt_token)
            if user_id is None:
                return Response({'error': 'Invalid token','status':401}, status=401)
            if role=='student':
               # user=Student.objects.filter(user_id=user_id)
                #old_password=user.password
                data=request.data
                serializers=PasswordtakingSerializer(data=data)
                if serializers.is_valid():
                    new_password=serializers.validated_data.get('password')
                    confirm_password=serializers.validated_data.get('confirm_password')
                    student=Student.objects.get(user_id=user_id)
                    print(student.password,new_password,confirm_password)
                    if student.password!=new_password:
                        if new_password==confirm_password:
                            student.password=new_password
                            student.save()
                            return Response({
                                'status': 201,
                                'message': 'Password changed successfully',
                                'data': serializers.data,
                            })
                        else:
                            return Response({
                                'status': 400,
                                'message': 'new password and confirm password not matched',
                                'data': serializers.errors,
                            })    
                    else:
                        return Response({
                            'status': 400,
                            'message': 'invalid',
                            'data': serializers.errors,
                        })    
                else:
                    return Response({
                        'status': 400,
                        'message': 'input data',
                        'data': serializers.errors,
                    })     
            else:
                return Response({'error': 'Access not allowed','status':405}, status=405)        
        else:
            return Response({'error': 'token not found','status':403}, status=403)              
        
    
    
#API for feedback form 
class feedbackformview(APIView):
    def get(self,request,*args,**kwargs):
        jwt_token=request.data.get('data', {}).get('token')
        jwt_token =request.data.get('token')
        #jwt_token = request.COOKIES.get('jwt_token')  
        if jwt_token:
            user_id, role = decode_jwt_token(jwt_token)
            if user_id is None:
                return Response({'error': 'Invalid token','status':401}, status=401)
            if role=='student':
                user=Student.objects.get(user_id=user_id)
                semester=user.semester
                year=user.Year
                section=user.section
                global user_data,subject_data
                #creating student data
                user_data={
                    'user_id':user_id,
                    'semester':semester,
                    'section':section,
                    
                }
                
                # now getting subject assigned to that student
                subjectuser=Subjects.objects.filter(semester=semester)
                if subjectuser==None:
                    return Response({'error': 'No subject data found','status':204}, status=204)
                subject_data = [{'subject_code': subject.code, 'sub_name': subject.name} for subject in subjectuser]
                #print(subject_data)
                
                for a in subject_data:
                    subassign={}
                    code=a['subject_code']
                    classassigneduser=classassigned.objects.get(subject_code=a['subject_code'],class_assigned=section,semester=semester)
                    facultyuser=Faculty.objects.get(user_id=classassigneduser.faculty)
                    if facultyuser==None:
                        faculty_name="Not Assigned"
                    faculty_name=facultyuser.first_name+" "+facultyuser.last_name
                    a["faculty"]=faculty_name
                
                
                return Response({"user_data":user_data,
                                 "subject_data":subject_data,
                                 "status":201},status=201)  
        else:
            return Response({'error': 'token not found','status':403}, status=403)
    def post(self,request,*args,**kwargs):
        try:
            #extracting data from request        
            feedback_data=request.data.get('feedback',[]) 
            
            # Validate that feedback_data is a list of dictionaries
            if not isinstance(feedback_data, list):
                return Response({'error': 'Invalid feedback data format','status':400}, status=status.HTTP_400_BAD_REQUEST)    
            
             # Validate that feedback_data contains feedback for at least one subject
            if not feedback_data:
                return Response({'error': 'Feedback for at least one subject is required','status':400}, status=status.HTTP_400_BAD_REQUEST)
            
            feedback_instances=[]
            for subject_feedback in feedback_data:
                subject_code=subject_feedback.get('subject_code')
                
                faculty_name = subject_feedback.get('faculty_name')
                
                feedback_instance=feedbacktable(
                    student_id=user_data['user_id'],
                    faculty_name=faculty_name,
                    year=user_data['semester'],
                    section=user_data['section'],
                    question1=subject_feedback['question_1'],
                    question2=subject_feedback['question_2'],
                    question3=subject_feedback['question_3'],
                    question4=subject_feedback['question_4'],
                    question5=subject_feedback['question_5'],   
                )
                feedback_instances.append(feedback_instance)
            feedbacktable.objects.bulk_create(feedback_instances) 
            return Response({'message': 'Feedback submitted successfully','status':201}, status=status.HTTP_201_CREATED)   
        
        except Exception as e:
            return Response({'error': str(e),'status':500}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)        
        
        
# API to get data of faculty
class getfacultydata(APIView):
    def get(self,request):
        jwt_token=request.data.get('data', {}).get('token')
        jwt_token =request.data.get('token')
        jwt_token = request.COOKIES.get('jwt_token')  
        if jwt_token:
            user_id, role = decode_jwt_token(jwt_token)
            print(user_id)
            if user_id is None:
                return Response({'error': 'Invalid token','status':401}, status=401)
            if role=='faculty':
                faculty_data=Faculty.objects.get(user_id=user_id)
                serializers=facultyeditorserializer(faculty_data)
                print(serializers.data)
                if not serializers.data:
                    return Response({'error': 'No data found','status':204}, status=204)
                return Response({"faculty_data":serializers.data,"status":201},status=201)
            else:
                return Response({'error': 'Access not allowed','status':405}, status=405)
            
        else:
            return Response({'error': 'token not found','status':403}, status=403)
            
        
"""         
class facultyattendance(APIView):
    def get(self,request)         """
       