package demo.data;

public interface UserRepository {
    String findByEmail(String email);
    String save(String entity);
}
