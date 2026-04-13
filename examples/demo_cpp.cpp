#include <string>

class Db {
public:
    void execute(std::string sql);
};

std::string source();
std::string sanitize(std::string x);

void handle(Db db) {
    std::string query = source();
    std::string safe = sanitize(query);
    db.execute(safe);
}
