from sqlalchemy import select

from app.core.config import DEMO_DATA
from app.db.models import Course, Professor, Schedule, Student


def scoped_courses(db, user):
    if user.role == "STUDENT":
        student = db.scalar(select(Student).where(Student.user_id == user.id))
        return (
            list(
                db.scalars(
                    select(Course).where(Course.class_name == student.class_name)
                )
            )
            if student
            else []
        )
    professor = db.scalar(select(Professor).where(Professor.user_id == user.id))
    return (
        list(db.scalars(select(Course).where(Course.professor_id == professor.id)))
        if professor
        else []
    )


def get_my_courses(db, user, **_):
    return [
        {"id": c.id, "course": c.name, "room": c.room} for c in scoped_courses(db, user)
    ]


def get_my_schedule(db, user, day=None):
    courses = {c.id: c for c in scoped_courses(db, user)}
    query = select(Schedule).where(Schedule.course_id.in_(courses))
    if day:
        query = query.where(Schedule.day == day)
    return [
        {
            "course": courses[s.course_id].name,
            "room": courses[s.course_id].room,
            "day": s.day,
            "start": s.start_time,
            "end": s.end_time,
        }
        for s in db.scalars(query.order_by(Schedule.day, Schedule.start_time))
    ]


def read_course_note(db, user, filename="normal_note.txt"):
    return {
        "source": filename,
        "content": (DEMO_DATA / filename).read_text(encoding="utf-8"),
    }
