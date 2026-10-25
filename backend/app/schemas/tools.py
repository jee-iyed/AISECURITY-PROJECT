from datetime import date, time, timedelta

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    field_validator,
    model_validator,
)

# Business constraint: the assistant only reasons about the current academic
# horizon; far-past or far-future dates are rejected rather than queried.
MAX_DAY_OFFSET = timedelta(days=366)
ROOM = r"^[AB][0-9]{3}$"


def _within_horizon(day):
    if day is not None and abs(day - date.today()) > MAX_DAY_OFFSET:
        raise ValueError("Date outside the supported academic horizon")
    return day


class Arguments(BaseModel):
    # Unknown fields (user_id, role, ...) are rejected: identity and privileges
    # only come from backend authentication.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Empty(Arguments):
    pass


class ScheduleArgs(Arguments):
    day: date | None = None

    _horizon = field_validator("day")(_within_horizon)


class CourseArgs(Arguments):
    # StrictInt: booleans, floats and numeric strings are not coerced.
    course_id: StrictInt = Field(default=1, ge=1, le=1_000_000)


class NoteArgs(Arguments):
    filename: str = Field(
        default="normal_note.txt", pattern=r"^(normal_note|malicious_note)\.txt$"
    )


class SearchArgs(Arguments):
    # Names only: letters (any script), spaces, hyphens, apostrophes and dots.
    query: str = Field(min_length=1, max_length=80, pattern=r"^[^\W\d_]+(?:[ .'\-][^\W\d_]+)*\.?$")


class RoomArgs(ScheduleArgs):
    room: str = Field(pattern=ROOM)


class FreeArgs(Arguments):
    day: date
    start_time: time
    end_time: time

    _horizon = field_validator("day")(_within_horizon)

    @model_validator(mode="after")
    def ordered(self):
        if any(
            t.second or t.microsecond or t.tzinfo
            for t in [self.start_time, self.end_time]
        ):
            raise ValueError("Use local times at whole-minute precision")
        if self.end_time <= self.start_time:
            raise ValueError("End must be after start")
        return self


class UpdateArgs(Arguments):
    course_id: StrictInt = Field(ge=1, le=1_000_000)
    old_room: str = Field(pattern=ROOM)
    new_room: str = Field(pattern=ROOM)
