from db import DB

primary, replica = (DB(), DB())
values = {"db": primary}


def get_db():
    return values["db"]
