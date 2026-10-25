from datetime import date, timedelta

from pwdlib import PasswordHash
from sqlalchemy import select

from app.core.config import DEMO_SCHEDULE_REFRESH
from app.db.models import Course, Professor, Schedule, Student, User

password_hash = PasswordHash.recommended()

DEMO_DOMAIN = "@esigelec-demo.fr"
# Each demo course meets daily at a fixed slot; the window rolls with the date.
DEMO_COURSES = {
    "Cybersecurity": ("A201", "09:00", "11:00"),
    "Reseaux": ("A201", "14:00", "16:00"),
}
DEMO_DAYS = 7


def seed(db, today=None):
    """Create the fictional demo data once, then keep its schedule current."""
    if not db.scalar(select(User.id).limit(1)):
        _create(db)
    if DEMO_SCHEDULE_REFRESH:
        refresh_demo_schedule(db, today)


def _create(db):
    users = [
        User(
            name=n,
            email=f"{role.lower()}{DEMO_DOMAIN}",
            role=role,
            hashed_password=password_hash.hash("DemoPass123!"),
        )
        for n, role in [
            ("Karim Demo", "STUDENT"),
            ("Alice Demo", "PROFESSOR"),
            ("Morgan Demo", "ADMIN"),
        ]
    ]
    db.add_all(users)
    db.flush()
    db.add(Student(user_id=users[0].id, class_name="ING2"))
    prof = Professor(user_id=users[1].id, department="Computer Science")
    db.add(prof)
    db.flush()
    for name, (room, _, _) in DEMO_COURSES.items():
        db.add(Course(name=name, professor_id=prof.id, class_name="ING2", room=room))
    db.commit()


def refresh_demo_schedule(db, today=None):
    """Add missing demo sessions for ``today`` .. ``today + DEMO_DAYS - 1``.

    Additive and idempotent: it only touches courses that belong to the
    fictional demo professor, only inserts sessions for days that have none,
    and never deletes rows, changes rooms (approved changes survive) or
    alters approvals. Returns the number of sessions added.
    """
    today = today or date.today()
    days = [(today + timedelta(days=offset)).isoformat() for offset in range(DEMO_DAYS)]
    demo_courses = db.scalars(
        select(Course)
        .join(Professor, Course.professor_id == Professor.id)
        .join(User, Professor.user_id == User.id)
        .where(User.email == "professor" + DEMO_DOMAIN, Course.name.in_(DEMO_COURSES))
    )
    added = 0
    for course in demo_courses:
        _, start, end = DEMO_COURSES[course.name]
        existing = set(
            db.scalars(
                select(Schedule.day).where(
                    Schedule.course_id == course.id, Schedule.day.in_(days)
                )
            )
        )
        for day in days:
            if day not in existing:
                db.add(Schedule(course_id=course.id, day=day, start_time=start, end_time=end))
                added += 1
    db.commit()
    return added
