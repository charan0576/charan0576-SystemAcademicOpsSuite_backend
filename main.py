from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Literal
from datetime import datetime, timedelta
from bson import ObjectId
import os
import bcrypt
import jwt
from dotenv import load_dotenv

load_dotenv()

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "campus_connect_hub")

# FastAPI App
app = FastAPI(title="Campus Connect Hub API", version="1.0.0")

# CORS Configuration
# In production set ALLOWED_ORIGINS=https://your-app.vercel.app in Render env vars
default_origins = "http://localhost:8080,http://localhost:5173,http://localhost:3000"
_raw_origins = os.getenv("ALLOWED_ORIGINS", default_origins)
allowed_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB Connection
client = AsyncIOMotorClient(MONGODB_URL)
db = client[DATABASE_NAME]
security = HTTPBearer()

# Helper Functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except:
        return False

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid user ID")
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    user["_id"] = str(user["_id"])
    user.pop("password", None)
    return user

# Pydantic Models
class UserRegister(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=6)
    role: Literal["student", "faculty"]
    department: str
    year: Optional[str] = None
    section: Optional[str] = None  # A, B, C, D — for students only

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class AttendanceCreate(BaseModel):
    student_id: str
    subject: str
    date: str
    status: Literal["present", "absent"]

class MarkCreate(BaseModel):
    student_id: str
    subject: str
    exam_type: str  # "mid", "assignment", "sem"
    exam_name: str  # "mid1", "mid2", "assignment1", "sem1", etc.
    marks_obtained: int = Field(..., ge=0)
    total_marks: int = Field(..., ge=1)

class DoubtCreate(BaseModel):
    subject: str
    question: str = Field(..., min_length=10)

class DoubtReply(BaseModel):
    reply: str = Field(..., min_length=5)

class ProfileUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    department: Optional[str] = None
    year: Optional[str] = None
    section: Optional[str] = None

class TimeSlot(BaseModel):
    time: str = Field(..., min_length=1)
    subject: str = Field(..., min_length=1)

class TimetableCreate(BaseModel):
    semester: int = Field(..., ge=1, le=8)
    schedule: dict[str, List[TimeSlot]]  # {"Monday": [{time, subject}], ...}

class TimetableUpdate(BaseModel):
    schedule: dict[str, List[TimeSlot]]

# API Endpoints

@app.get("/")
async def root():
    return {
        "message": "Campus Connect Hub API",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
async def health_check():
    try:
        await db.command("ping")
        return {"status": "healthy", "database": "connected"}
    except:
        return {"status": "unhealthy", "database": "disconnected"}

# ============ AUTH ENDPOINTS ============

@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegister):
    """Register a new user"""
    # Check if email already exists
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user document
    user_doc = {
        "name": user_data.name,
        "email": user_data.email,
        "password": hash_password(user_data.password),
        "role": user_data.role,
        "department": user_data.department,
        "year": user_data.year,
        "section": user_data.section if user_data.role == "student" else None,
        "created_at": datetime.utcnow(),
    }
    
    result = await db.users.insert_one(user_doc)
    user_id = str(result.inserted_id)
    
    # Create access token
    access_token = create_access_token({"sub": user_id})
    
    # Return user profile
    profile = {
        "id": user_id,
        "user_id": user_id,
        "name": user_data.name,
        "email": user_data.email,
        "role": user_data.role,
        "department": user_data.department,
        "year": user_data.year,
        "section": user_data.section if user_data.role == "student" else None,
    }
    
    return {
        "user": {"id": user_id, "email": user_data.email},
        "profile": profile,
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.post("/api/auth/login")
async def login(credentials: UserLogin):
    """Login user"""
    user = await db.users.find_one({"email": credentials.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user_id = str(user["_id"])
    access_token = create_access_token({"sub": user_id})
    
    # Return user profile
    profile = {
        "id": user_id,
        "user_id": user_id,
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "department": user["department"],
        "year": user.get("year"),
        "section": user.get("section"),
    }
    
    return {
        "user": {"id": user_id, "email": user["email"]},
        "profile": profile,
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.post("/api/auth/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Logout user"""
    return {"message": "Logged out successfully"}

@app.get("/api/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current user profile"""
    profile = {
        "id": current_user["_id"],
        "user_id": current_user["_id"],
        "name": current_user["name"],
        "email": current_user["email"],
        "role": current_user["role"],
        "department": current_user["department"],
        "year": current_user.get("year"),
        "section": current_user.get("section"),
    }
    return {"profile": profile}

@app.patch("/api/auth/profile")
async def update_profile(
    data: ProfileUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update the current user profile (name, department, year)"""
    update_fields = {}
    if data.name is not None:
        update_fields["name"] = data.name
    if data.department is not None:
        update_fields["department"] = data.department
    if data.year is not None:
        update_fields["year"] = data.year
    if data.section is not None:
        update_fields["section"] = data.section

    if not update_fields:
        raise HTTPException(status_code=400, detail="No fields to update")

    await db.users.update_one(
        {"_id": ObjectId(current_user["_id"])},
        {"$set": update_fields}
    )

    updated_user = await db.users.find_one({"_id": ObjectId(current_user["_id"])})
    updated_user["_id"] = str(updated_user["_id"])
    profile = {
        "id": updated_user["_id"],
        "user_id": updated_user["_id"],
        "name": updated_user["name"],
        "email": updated_user["email"],
        "role": updated_user["role"],
        "department": updated_user["department"],
        "year": updated_user.get("year"),
        "section": updated_user.get("section"),
    }
    return {"profile": profile}

# ============ STUDENT ENDPOINTS ============

@app.get("/api/students")
async def get_students(
    section: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get all students from faculty's department (Faculty only), optionally filtered by section"""
    if current_user.get("role") != "faculty":
        raise HTTPException(status_code=403, detail="Only faculty can view students")
    
    # Get faculty's department
    faculty_department = current_user.get("department")
    
    # Build query — optionally filter by section
    query: dict = {"role": "student", "department": faculty_department}
    if section:
        query["section"] = section

    # Filter students by the same department as faculty
    students = []
    async for student in db.users.find(query):
        student["_id"] = str(student["_id"])
        student.pop("password", None)
        students.append(student)
    
    return students

# ============ ATTENDANCE ENDPOINTS ============

@app.post("/api/attendance", status_code=status.HTTP_201_CREATED)
async def mark_attendance(
    attendance: AttendanceCreate,
    current_user: dict = Depends(get_current_user)
):
    """Mark attendance (Faculty only - same department students)"""
    if current_user.get("role") != "faculty":
        raise HTTPException(status_code=403, detail="Only faculty can mark attendance")
    
    # Get student information
    try:
        student = await db.users.find_one({"_id": ObjectId(attendance.student_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid student ID")
    
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    
    # Check if student is from the same department as faculty
    faculty_department = current_user.get("department")
    if student.get("department") != faculty_department:
        raise HTTPException(
            status_code=403, 
            detail=f"You can only mark attendance for students in your department ({faculty_department})"
        )
    
    # Upsert: one record per student/subject/date — clicking multiple times won't duplicate
    filter_query = {
        "student_id": attendance.student_id,
        "subject": attendance.subject,
        "date": attendance.date,
    }
    update_doc = {
        "$set": {
            "student_name": student["name"],
            "status": attendance.status,
            "marked_by": current_user["_id"],
            "faculty_name": current_user["name"],
            "updated_at": datetime.utcnow(),
        },
        "$setOnInsert": {
            "created_at": datetime.utcnow(),
        }
    }
    result = await db.attendance.find_one_and_update(
        filter_query,
        update_doc,
        upsert=True,
        return_document=True,
    )
    if result:
        result["_id"] = str(result["_id"])
        return result

    # Fallback: return the newly inserted doc
    inserted = await db.attendance.find_one(filter_query)
    inserted["_id"] = str(inserted["_id"])
    return inserted

@app.get("/api/attendance/student/{student_id}")
async def get_student_attendance(
    student_id: str,
    subject: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get attendance records for a student"""
    # Students can only view their own attendance
    if current_user.get("role") == "student" and current_user["_id"] != student_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    query = {"student_id": student_id}
    if subject:
        query["subject"] = subject
    
    records = []
    async for record in db.attendance.find(query).sort("date", -1):
        record["_id"] = str(record["_id"])
        records.append(record)
    
    return records

@app.get("/api/attendance/percentage/{student_id}")
async def get_attendance_percentage(
    student_id: str,
    subject: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Calculate attendance percentage"""
    if current_user.get("role") == "student" and current_user["_id"] != student_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    query = {"student_id": student_id}
    if subject:
        query["subject"] = subject
    
    total = await db.attendance.count_documents(query)
    if total == 0:
        return {"percentage": 0, "total": 0, "present": 0}
    
    query["status"] = "present"
    present = await db.attendance.count_documents(query)
    
    percentage = round((present / total) * 100, 2)
    
    return {
        "percentage": percentage,
        "total": total,
        "present": present
    }

# ============ MARKS ENDPOINTS ============

@app.post("/api/marks", status_code=status.HTTP_201_CREATED)
async def insert_marks(
    mark: MarkCreate,
    current_user: dict = Depends(get_current_user)
):
    """Insert marks (Faculty only - same department students)"""
    if current_user.get("role") != "faculty":
        raise HTTPException(status_code=403, detail="Only faculty can insert marks")
    
    # Validate marks
    if mark.marks_obtained > mark.total_marks:
        raise HTTPException(status_code=400, detail="Marks obtained cannot exceed total marks")
    
    # Verify student exists and is from the same department
    try:
        student = await db.users.find_one({"_id": ObjectId(mark.student_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid student ID")
    
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    
    # Check if student is from the same department as faculty
    faculty_department = current_user.get("department")
    if student.get("department") != faculty_department:
        raise HTTPException(
            status_code=403, 
            detail=f"You can only enter marks for students in your department ({faculty_department})"
        )
    
    # Upsert: one mark per student/subject/exam_name — re-saving updates existing record
    filter_q = {
        "student_id": mark.student_id,
        "subject": mark.subject,
        "exam_name": mark.exam_name,
    }
    update_doc = {
        "$set": {
            "exam_type": mark.exam_type,
            "marks_obtained": mark.marks_obtained,
            "total_marks": mark.total_marks,
            "marked_by": current_user["_id"],
            "updated_at": datetime.utcnow(),
        },
        "$setOnInsert": {
            "created_at": datetime.utcnow(),
        }
    }
    result = await db.marks.find_one_and_update(
        filter_q,
        update_doc,
        upsert=True,
        return_document=True,
    )
    if result:
        result["_id"] = str(result["_id"])
        return result
    inserted = await db.marks.find_one(filter_q)
    inserted["_id"] = str(inserted["_id"])
    return inserted

@app.get("/api/marks/student/{student_id}")
async def get_student_marks(
    student_id: str,
    subject: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get marks for a student"""
    if current_user.get("role") == "student" and current_user["_id"] != student_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    query = {"student_id": student_id}
    if subject:
        query["subject"] = subject
    
    marks = []
    async for mark in db.marks.find(query).sort("created_at", -1):
        mark["_id"] = str(mark["_id"])
        marks.append(mark)
    
    return marks

# ============ DOUBTS ENDPOINTS ============

@app.post("/api/doubts", status_code=status.HTTP_201_CREATED)
async def create_doubt(
    doubt: DoubtCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a doubt (Student only)"""
    if current_user.get("role") != "student":
        raise HTTPException(status_code=403, detail="Only students can create doubts")
    
    doubt_doc = {
        "student_id": current_user["_id"],
        "student_name": current_user["name"],
        "subject": doubt.subject,
        "question": doubt.question,
        "reply": None,
        "replied_by": None,
        "created_at": datetime.utcnow().isoformat(),
        "replied_at": None
    }
    
    result = await db.doubts.insert_one(doubt_doc)
    doubt_doc["_id"] = str(result.inserted_id)
    
    return doubt_doc

@app.get("/api/doubts/student/{student_id}")
async def get_student_doubts(
    student_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get doubts for a student"""
    if current_user.get("role") == "student" and current_user["_id"] != student_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    doubts = []
    async for doubt in db.doubts.find({"student_id": student_id}).sort("created_at", -1):
        doubt["_id"] = str(doubt["_id"])
        doubts.append(doubt)
    
    return doubts

@app.get("/api/doubts")
async def get_all_doubts(current_user: dict = Depends(get_current_user)):
    """Get all doubts from students in faculty's department (Faculty only)"""
    if current_user.get("role") != "faculty":
        raise HTTPException(status_code=403, detail="Only faculty can view all doubts")
    
    # Get faculty's department
    faculty_department = current_user.get("department")
    
    # First, get all student IDs from the faculty's department
    student_ids = []
    async for student in db.users.find({
        "role": "student",
        "department": faculty_department
    }):
        student_ids.append(str(student["_id"]))
    
    # Then, get doubts only from those students
    doubts = []
    async for doubt in db.doubts.find({
        "student_id": {"$in": student_ids}
    }).sort("created_at", -1):
        doubt["_id"] = str(doubt["_id"])
        doubts.append(doubt)
    
    return doubts

@app.patch("/api/doubts/{doubt_id}/reply")
async def reply_to_doubt(
    doubt_id: str,
    reply_data: DoubtReply,
    current_user: dict = Depends(get_current_user)
):
    """Reply to a doubt (Faculty only - same department students)"""
    if current_user.get("role") != "faculty":
        raise HTTPException(status_code=403, detail="Only faculty can reply to doubts")
    
    try:
        doubt = await db.doubts.find_one({"_id": ObjectId(doubt_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid doubt ID")
    
    if not doubt:
        raise HTTPException(status_code=404, detail="Doubt not found")
    
    # Check if the doubt is from a student in the faculty's department
    try:
        student = await db.users.find_one({"_id": ObjectId(doubt["student_id"])})
    except:
        raise HTTPException(status_code=400, detail="Invalid student ID in doubt")
    
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    
    faculty_department = current_user.get("department")
    if student.get("department") != faculty_department:
        raise HTTPException(
            status_code=403, 
            detail=f"You can only reply to doubts from students in your department ({faculty_department})"
        )
    
    await db.doubts.update_one(
        {"_id": ObjectId(doubt_id)},
        {"$set": {
            "reply": reply_data.reply,
            "replied_by": current_user["name"],
            "replied_at": datetime.utcnow().isoformat()
        }}
    )
    
    return {"message": "Reply added successfully"}

# ============ TIMETABLE ENDPOINTS ============

@app.post("/api/timetable", status_code=status.HTTP_201_CREATED)
async def create_timetable(
    timetable_data: TimetableCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create timetable (Faculty only - for their department)"""
    if current_user.get("role") != "faculty":
        raise HTTPException(status_code=403, detail="Only faculty can create timetables")
    
    faculty_department = current_user.get("department")
    
    # Check if timetable already exists for this department and semester
    existing = await db.timetables.find_one({
        "department": faculty_department,
        "semester": timetable_data.semester
    })
    
    if existing:
        raise HTTPException(
            status_code=400, 
            detail=f"Timetable already exists for {faculty_department} Semester {timetable_data.semester}. Use update endpoint instead."
        )
    
    # Convert TimeSlot objects to dicts
    schedule_dict = {}
    for day, slots in timetable_data.schedule.items():
        schedule_dict[day] = [{"time": slot.time, "subject": slot.subject} for slot in slots]
    
    timetable_doc = {
        "department": faculty_department,
        "semester": timetable_data.semester,
        "schedule": schedule_dict,
        "created_by": current_user["_id"],
        "created_by_name": current_user["name"],
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    result = await db.timetables.insert_one(timetable_doc)
    timetable_doc["_id"] = str(result.inserted_id)
    
    return timetable_doc

@app.get("/api/timetable/{semester}")
async def get_timetable(
    semester: int,
    current_user: dict = Depends(get_current_user)
):
    """Get timetable for a specific semester and department"""
    # Students and faculty from same department can view
    user_department = current_user.get("department")
    
    timetable = await db.timetables.find_one({
        "department": user_department,
        "semester": semester
    })
    
    if not timetable:
        raise HTTPException(
            status_code=404, 
            detail=f"No timetable found for {user_department} Semester {semester}"
        )
    
    timetable["_id"] = str(timetable["_id"])
    return timetable

@app.get("/api/timetables")
async def get_all_timetables(current_user: dict = Depends(get_current_user)):
    """Get all timetables for user's department"""
    user_department = current_user.get("department")
    
    timetables = []
    async for timetable in db.timetables.find({
        "department": user_department
    }).sort("semester", 1):
        timetable["_id"] = str(timetable["_id"])
        timetables.append(timetable)
    
    return timetables

@app.put("/api/timetable/{semester}")
async def update_timetable(
    semester: int,
    timetable_data: TimetableUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update timetable (Faculty only - for their department)"""
    if current_user.get("role") != "faculty":
        raise HTTPException(status_code=403, detail="Only faculty can update timetables")
    
    faculty_department = current_user.get("department")
    
    # Check if timetable exists
    existing = await db.timetables.find_one({
        "department": faculty_department,
        "semester": semester
    })
    
    if not existing:
        raise HTTPException(
            status_code=404, 
            detail=f"No timetable found for {faculty_department} Semester {semester}"
        )
    
    # Convert TimeSlot objects to dicts
    schedule_dict = {}
    for day, slots in timetable_data.schedule.items():
        schedule_dict[day] = [{"time": slot.time, "subject": slot.subject} for slot in slots]
    
    await db.timetables.update_one(
        {"department": faculty_department, "semester": semester},
        {"$set": {
            "schedule": schedule_dict,
            "updated_at": datetime.utcnow(),
            "updated_by": current_user["_id"],
            "updated_by_name": current_user["name"]
        }}
    )
    
    return {"message": "Timetable updated successfully"}

@app.delete("/api/timetable/{semester}")
async def delete_timetable(
    semester: int,
    current_user: dict = Depends(get_current_user)
):
    """Delete timetable (Faculty only - for their department)"""
    if current_user.get("role") != "faculty":
        raise HTTPException(status_code=403, detail="Only faculty can delete timetables")
    
    faculty_department = current_user.get("department")
    
    result = await db.timetables.delete_one({
        "department": faculty_department,
        "semester": semester
    })
    
    if result.deleted_count == 0:
        raise HTTPException(
            status_code=404, 
            detail=f"No timetable found for {faculty_department} Semester {semester}"
        )
    
    return {"message": "Timetable deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

# ============ DELETE ENDPOINTS (Faculty) ============

@app.delete("/api/attendance/{attendance_id}")
async def delete_attendance_record(
    attendance_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a single attendance record (Faculty only)"""
    if current_user.get("role") != "faculty":
        raise HTTPException(status_code=403, detail="Only faculty can delete attendance records")
    try:
        result = await db.attendance.delete_one({"_id": ObjectId(attendance_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid attendance ID")
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Attendance record not found")
    return {"message": "Attendance record deleted"}


@app.delete("/api/marks/{mark_id}")
async def delete_mark_record(
    mark_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a single marks record (Faculty only)"""
    if current_user.get("role") != "faculty":
        raise HTTPException(status_code=403, detail="Only faculty can delete marks")
    try:
        result = await db.marks.delete_one({"_id": ObjectId(mark_id)})
    except:
        raise HTTPException(status_code=400, detail="Invalid mark ID")
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Mark record not found")
    return {"message": "Mark record deleted"}


@app.get("/api/attendance/all/by-faculty")
async def get_all_attendance_by_faculty(
    current_user: dict = Depends(get_current_user)
):
    """Get all attendance records for faculty's department students"""
    if current_user.get("role") != "faculty":
        raise HTTPException(status_code=403, detail="Only faculty can view all attendance")
    faculty_department = current_user.get("department")
    student_ids = []
    async for student in db.users.find({"role": "student", "department": faculty_department}):
        student_ids.append(str(student["_id"]))
    records = []
    async for record in db.attendance.find({"student_id": {"$in": student_ids}}).sort("date", -1):
        record["_id"] = str(record["_id"])
        records.append(record)
    return records
