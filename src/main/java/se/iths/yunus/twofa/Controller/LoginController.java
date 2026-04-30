package se.iths.yunus.twofa.Controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import se.iths.yunus.twofa.model.AppUser;
import se.iths.yunus.twofa.repository.AppUserRepository;
import se.iths.yunus.twofa.service.TwoFactorService;

import java.util.List;

@Controller
public class LoginController {

    private final AppUserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final TwoFactorService twoFactorService;

    private final SecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();

    public LoginController(AppUserRepository repository,
                           PasswordEncoder passwordEncoder,
                           TwoFactorService twoFactorService) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.twoFactorService = twoFactorService;
    }

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/login")
    public String loginPage(@RequestParam(required = false) String logout,
                            Model model) {
        if (logout != null) {
            model.addAttribute("message", "You have been logged out.");
        }
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String email,
                        @RequestParam String password,
                        HttpSession session,
                        Model model,
                        HttpServletRequest request,
                        HttpServletResponse response) {

        AppUser user = repository.findByEmail(email).orElse(null);

        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            model.addAttribute("error", "Invalid email or password");
            return "login";
        }

        if (user.isTwoFactorEnabled()) {
            session.setAttribute("2fa_user_email", user.getEmail());
            return "redirect:/verify-2fa";
        }

        authenticateUser(user, request, response);
        return "redirect:/";
    }

    @GetMapping("/verify-2fa")
    public String verify2faPage(HttpSession session) {
        if (session.getAttribute("2fa_user_email") == null) {
            return "redirect:/login";
        }

        return "verify-2fa";
    }

    @PostMapping("/verify-2fa")
    public String verify2fa(@RequestParam int code,
                            HttpSession session,
                            Model model,
                            HttpServletRequest request,
                            HttpServletResponse response) {

        String email = (String) session.getAttribute("2fa_user_email");

        if (email == null) {
            return "redirect:/login";
        }

        AppUser user = repository.findByEmail(email).orElse(null);

        if (user == null) {
            return "redirect:/login";
        }

        boolean valid = twoFactorService.verifyCode(user.getTwoFactorSecret(), code);

        if (!valid) {
            model.addAttribute("error", "Invalid authentication code");
            return "verify-2fa";
        }

        session.removeAttribute("2fa_user_email");
        authenticateUser(user, request, response);

        return "redirect:/";
    }

    private void authenticateUser(AppUser user,
                                  HttpServletRequest request,
                                  HttpServletResponse response) {

        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(
                        user.getEmail(),
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole()))
                );

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(auth);
        SecurityContextHolder.setContext(context);

        securityContextRepository.saveContext(context, request, response);
    }
}