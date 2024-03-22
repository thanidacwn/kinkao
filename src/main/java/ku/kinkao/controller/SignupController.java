package ku.kinkao.controller;


import ku.kinkao.entity.Member;
import ku.kinkao.service.SignupService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;


@Controller
public class SignupController {


    @Autowired
    private SignupService signupService;


    @GetMapping("/signup")
    public String getSignupPage() {
        return "signup"; // return signup.html
    }


    @PostMapping("/signup")
    public String signupMember(@ModelAttribute Member member, Model model) {


        if (signupService.isUsernameAvailable(member.getUsername())) {
            signupService.createMember(member);
            model.addAttribute("signupSuccess", true);
        } else {
            model.addAttribute("signupError", "Username not available");
        }


        // return signup.html but there will be message appearing
        return "signup";
    }
}

