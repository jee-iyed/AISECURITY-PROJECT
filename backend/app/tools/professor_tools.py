from sqlalchemy import select

from app.db.models import Student, User
from app.tools.student_tools import scoped_courses


def get_course_students(db, user, course_id):
    course = next(c for c in scoped_courses(db, user) if c.id == course_id)
    return [
        {"name": u.name, "class_name": s.class_name}
        for s, u in db.execute(
            select(Student, User)
            .join(User, Student.user_id == User.id)
            .where(Student.class_name == course.class_name)
        )
    ]
