package blue.spring.security.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class SomeController {

    @RequestMapping("/me")
    public Principal user(Principal user)
    {
        return user;
    }
}

@Controller
class WebController {

    @RequestMapping("/")
    public String index(Model model, Principal user)
    {
        model.addAttribute("user", user);
        return "index.html";
    }

}
