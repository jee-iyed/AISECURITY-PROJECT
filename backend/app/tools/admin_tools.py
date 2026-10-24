from sqlalchemy import select

from app.db.models import Course, Schedule, User

ROOMS = {"A201", "A202", "B105", "B106"}


def search_student(db, user, query):
    return search(db, "STUDENT", query)


def search_professor(db, user, query):
    return search(db, "PROFESSOR", query)


def search(db, role, query):
    return [
        {"id": u.id, "name": u.name, "email": u.email}
        for u in db.scalars(
            select(User).where(
                User.role == role, User.name.contains(query, autoescape=True)
            )
        )
    ]


def get_room_schedule(db, user, room, day=None):
    query = select(Schedule, Course).join(Course).where(Course.room == room)
    if day:
        query = query.where(Schedule.day == day)
    return [
        {
            "course_id": c.id,
            "course": c.name,
            "day": s.day,
            "start": s.start_time,
            "end": s.end_time,
            "room": c.room,
        }
        for s, c in db.execute(query)
    ]


def find_free_room(db, user, day, start_time, end_time):
    occupied = set(
        db.scalars(
            select(Course.room)
            .join(Schedule)
            .where(
                Schedule.day == day,
                Schedule.start_time < end_time,
                Schedule.end_time > start_time,
            )
        )
    )
    return {
        "day": day,
        "start": start_time,
        "end": end_time,
        "free_rooms": sorted(ROOMS - occupied),
    }


def update_schedule(db, user, course_id, old_room, new_room):
    course = db.get(Course, course_id)
    course.room = new_room
    return {"course": course.name, "old_room": old_room, "new_room": new_room}
