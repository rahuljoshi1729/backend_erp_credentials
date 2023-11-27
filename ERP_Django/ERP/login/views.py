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
class register(APIView):
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
                        return JsonResponse({'error': 'User not found','status':404}, status=404)
                    user = faculty
                else:
                    user = student

                if user.password == password:
                    email=user.email
                    send_otp_via_email(email,user_id,password)
                    return HttpResponse({'message': 'OTP sent to email','status':201},status=201)

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
                email=serializers.validated_data['email']
                #checking in loginuser model
                user=LoginUser.objects.filter(otp=otp).first()
                
                if user:
                    
                    #fetching user_id form student/Faculty model
                    student = Student.objects.filter(email=email).first()
                    if not student:
                        faculty = Faculty.objects.filter(email=email).first()
                        if not faculty:
                            return JsonResponse({'error': 'User not found','status':404})
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
                    response = JsonResponse({'user_id': user_id, 'otp_sent': True, 'token': token,'status':201})
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

                if not student_user and not faculty_user:
                    return JsonResponse({'error': 'User not found: unauthorized email','status':404}, status=404)

                # Assuming you have a function to send password reset mail
                print(email)
                token=send_passwordreset_mail(email)

                return JsonResponse({'message': 'Password reset link sent to email',
                                     'token':token,'status':201},status=201)

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
                token = request.data.get('data', {}).get('token')
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
    #print(request.headers)
    #print(request.META)
    print(request.headers.get('Authorization'))
    jwt_token = request.headers.get('token')
    print(request.data)

    jwt_token = request.data.get('data', {}).get('token')
    print(jwt_token)
    
    
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
                                "total_classes":total_classes,
                                "present":present,
                                "absent":total_classes-present,
                                "data":data,
                                "status":201},status=201) 
                
            except jwt.ExpiredSignatureError:  
                return JsonResponse({'error': 'Token expired','status':401}, status=401)
    else:
            return JsonResponse({'error': 'Invalid token','status':401}, status=401)      

@api_view(['GET'])
def get_examdata(request):
    user_id='2210085194'
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
                     "admit_card_result_data":extracted_data})
    
    
