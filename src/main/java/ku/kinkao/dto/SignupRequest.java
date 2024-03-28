package ku.kinkao.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;


import ku.kinkao.validation.ValidPassword;
import lombok.Data;


@Data
public class SignupRequest {


    @NotBlank
    @Size(min=4, message = "Username must have at least 4 characters")
    private String username;


    @NotBlank
    @Size(min=12, max=128, message = "Password must have at least 12 characters")
    @ValidPassword
    private String password;


    @NotBlank(message = "First name is required")
    @Pattern(regexp = "^[a-zA-Z]+$",
            message = "First name can only contain letters")
    private String firstName;


    @NotBlank
    private String lastName;

    @Email
    @NotBlank
    private String email;
}
