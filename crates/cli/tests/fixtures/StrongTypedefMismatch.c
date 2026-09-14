typedef int UserId;
typedef int GroupId;

void accept_user(UserId value) {}

UserId default_user(void) {
    GroupId group = 1;
    return group;
}

int combine(UserId user, GroupId group) {
    accept_user(group);
    return user + group;
}
