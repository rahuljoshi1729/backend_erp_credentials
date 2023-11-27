from django.contrib import admin
from django.urls import path,include
from .views import *

urlpatterns = [
   # path('upload/', ImageUploadView.as_view(), name='image-upload'),
    path('login/',login.as_view(),name='register'),
    path('studentdataeditor/',studentdataeditor.as_view(),name='dataeditor'),
    path('facultyeditor/',facultyeditor.as_view(),name='faculty_data'),
    path('subjecteditor/',subjecteditor.as_view(),name='dataeditor'),
    path('attendanceeditor/',attendanceeditor.as_view(),name='dataeditor'),
    path('exameditor/',examdataeditiorview.as_view(),name='exam_data'),
    path('examdataadmitresult/',examdataadmitresulteditiorview.as_view(),name='exam_data'),
    path('classassign/',classassignview.as_view(),name='classassign'),
    path('examdata/',get_examdata,name='exam_data'),
    path("verifyotp/",VerifyOTP.as_view(),name="verifyotp"),
    path("passwordreset/",PasswordResetRequest.as_view(),name="passwordresetrequest"),
    path("password/reset/",PasswordReset.as_view(),name="passwordreset"),
    path("attendance/",Attendanceview,name="attendance"),
    path("postevent/",eventpostview.as_view(),name="postevent"),
    path("getevent/",geteventdataview.as_view(),name="getevent"),
    path("uploadtimetable/",timetableuploader.as_view(),name="timetable"),
    path("gettimetable/",gettimetable.as_view(),name="gettimetable"),]
    
