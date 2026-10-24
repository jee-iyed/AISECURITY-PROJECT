from datetime import date, time

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Empty(Arguments):
    pass


class ScheduleArgs(Arguments):
    day: date | None = None


class CourseArgs(Arguments):
    course_id: int = Field(default=1, ge=1)


class NoteArgs(Arguments):
    filename: str = Field(
        default="normal_note.txt", pattern=r"^(normal_note|malicious_note)\.txt$"
    )


class SearchArgs(Arguments):
    query: str = Field(min_length=1, max_length=80)


class RoomArgs(ScheduleArgs):
    room: str = Field(pattern=r"^[AB][0-9]{3}$")


class FreeArgs(Arguments):
    day: date
    start_time: time
    end_time: time

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
    course_id: int = Field(ge=1)
    old_room: str = Field(pattern=r"^[AB][0-9]{3}$")
    new_room: str = Field(pattern=r"^[AB][0-9]{3}$")
