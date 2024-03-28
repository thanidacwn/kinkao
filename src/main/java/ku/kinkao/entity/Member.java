package ku.kinkao.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Data;

import java.time.Instant;
import java.util.UUID;

@Data
@Entity
public class Member {


    @Id
    @GeneratedValue
    private UUID id;

    private String username;
    private String password;
    private String firstName;
    private String lastName;

    private String email;

    private Instant createdAt;


}
