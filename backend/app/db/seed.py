from datetime import date, timedelta

from pwdlib import PasswordHash
from sqlalchemy import select

from app.db.models import Course, Professor, Schedule, Student, User

password_hash = PasswordHash.recommended()


def seed(db):
    if db.scalar(select(User.id).limit(1)):
        return
    users = [
        User(
            name=n,
            email=f"{role.lower()}@esigelec-demo.fr",
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
    for name, room, start, end in [
        ("Cybersecurity", "A201", "09:00", "11:00"),
        ("Reseaux", "A201", "14:00", "16:00"),
    ]:
        c = Course(name=name, professor_id=prof.id, class_name="ING2", room=room)
        db.add(c)
        db.flush()
        for offset in range(7):
            db.add(
                Schedule(
                    course_id=c.id,
                    day=(date.today() + timedelta(days=offset)).isoformat(),
                    start_time=start,
                    end_time=end,
                )
            )
    db.commit()
